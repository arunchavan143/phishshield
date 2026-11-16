from unittest.mock import patch

import pytest

from engine import URLAnalyzer
from networking import CollectionError, DeadlineExceeded, DestinationBlocked, HeaderResponse


def collect(url='https://example.com', responses=None, **settings):
    with patch('engine.resolve_public', return_value=['93.184.216.34']), patch(
        'engine.request_headers', side_effect=responses or [HeaderResponse(200, None, '93.184.216.34')]
    ):
        return URLAnalyzer(url, **settings).analyze()


@pytest.mark.parametrize('url', ['javascript:alert(1)', 'ftp://example.com', 'https://u:p@example.com', 'https://@example.com', 'https://example.com:0', 'https://example.com:65536', 'https://example.com/\npath', 'https://example.com\\@internal', 'https://[::1%25eth0]', 'https://%31%32%37.0.0.1'])
def test_invalid_urls_are_rejected(url):
    with pytest.raises(ValueError):
        URLAnalyzer(url)


def test_bare_host_port_and_unicode_are_canonicalized():
    assert URLAnalyzer.normalize_url('example.com:443/login') == 'https://example.com:443/login'
    assert URLAnalyzer.normalize_url('https://bücher.de') == 'https://xn--bcher-kva.de'


def test_complete_report_distinguishes_coverage_from_confidence():
    report = collect('https://secure-login.example.com/login')
    assert 'SUSPICIOUS_TERMS' in {item['rule_id'] for item in report['evidence']}
    assert report['coverage']['percent'] == 100
    assert report['coverage']['checks']['reputation'] == 'disabled'
    assert report['detection_confidence'] is None
    assert report['settings']['enable_reputation'] is False
    assert report['case_id']


@pytest.mark.parametrize('url', ['https://paypal.example.org', 'https://google.example.com', 'https://secure-login-google.example/verify', 'https://paypal.net'])
def test_brand_impersonation_is_detected(url):
    evidence, _ = URLAnalyzer(url, static_only=True)._static_evidence()
    assert 'BRAND_TERM_IN_UNTRUSTED_HOST' in {item.rule_id for item in evidence}


def test_known_brand_domain_does_not_trigger_impersonation():
    assert URLAnalyzer('https://accounts.google.com')._brand_evidence() is None


def test_private_psl_tenants_are_not_treated_as_same_domain():
    assert URLAnalyzer('https://paypal.github.io').registered_domain == 'paypal.github.io'


def test_idn_is_not_double_counted():
    report = URLAnalyzer('https://bücher.de', static_only=True).analyze()
    rules = [item['rule_id'] for item in report['evidence']]
    assert rules.count('PUNYCODE_HOST') == 1
    assert 'UNICODE_HOST' not in rules


def test_disabled_network_has_stable_schema():
    report = collect(follow_redirects=False)
    network = report['network']
    assert network['status'] == 'disabled'
    assert network['final_url'] is None
    assert network['error'] is None
    assert network['status_code'] is None
    assert network['response_time_ms'] is None
    assert report['coverage']['attempted_checks'] == 2


def test_static_mode_makes_no_network_or_reputation_calls():
    with patch('engine.resolve_public') as dns, patch('engine.request_headers') as http, patch('engine.check_reputation') as reputation:
        report = URLAnalyzer('https://example.com', static_only=True, enable_reputation=True).analyze()
    dns.assert_not_called()
    http.assert_not_called()
    reputation.assert_not_called()
    assert report['coverage']['attempted_checks'] == 1
    assert report['coverage']['checks']['dns'] == 'disabled'


def test_failure_keeps_observed_redirect_chain_and_hop_evidence():
    report = collect(responses=[HeaderResponse(302, 'https://paypal.example.org/login', '93.184.216.34'), CollectionError('HTTP collection failed.')])
    assert report['network']['status'] == 'failed'
    assert report['network']['redirect_chain'][-1] == 'https://paypal.example.org/login'
    assert len(report['network']['hops']) == 1
    assert any(item['rule_id'] == 'BRAND_TERM_IN_UNTRUSTED_HOST' and item['subject_url'] == 'https://paypal.example.org/login' for item in report['evidence'])
    assert report['coverage']['status'] == 'partial'


def test_private_redirect_is_blocked_before_second_connection():
    def resolve(host, *args):
        if host == 'internal.example':
            raise DestinationBlocked('Outbound policy blocked a non-public address.')
        return ['93.184.216.34']
    with patch('engine.resolve_public', side_effect=resolve), patch('engine.request_headers', return_value=HeaderResponse(302, 'http://internal.example', '93.184.216.34')) as http:
        report = URLAnalyzer('https://example.com').analyze()
    assert report['network']['status'] == 'blocked'
    assert report['network']['blocked_url'] == 'http://internal.example'
    assert http.call_count == 1


def test_redirect_limit_preserves_observations():
    report = collect(responses=[HeaderResponse(302, '/again', '93.184.216.34')], max_redirects=0)
    assert report['network']['status'] == 'failed'
    assert report['network']['hops'][0]['status_code'] == 302
    assert 'REDIRECT_LIMIT_EXCEEDED' in {item['rule_id'] for item in report['evidence']}


def test_same_host_redirect_uses_pinned_dns_answer():
    with patch('engine.resolve_public', return_value=['93.184.216.34']) as dns, patch('engine.request_headers', side_effect=[HeaderResponse(302, '/final', '93.184.216.34'), HeaderResponse(200, None, '93.184.216.34')]) as http:
        report = URLAnalyzer('https://example.com').analyze()
    assert dns.call_count == 1
    assert all(call.args[1] == '93.184.216.34' for call in http.call_args_list)
    assert report['network']['status'] == 'complete'


def test_unconfigured_requested_reputation_reduces_coverage():
    with patch.dict('os.environ', {}, clear=True):
        report = collect(enable_reputation=True)
    assert report['coverage']['attempted_checks'] == 4
    assert report['coverage']['percent'] == 75
    assert report['coverage']['status'] == 'partial'


def test_dns_deadline_is_reported_without_http_request():
    with patch('engine.resolve_public', side_effect=DeadlineExceeded('DNS collection timed out.')), patch('engine.request_headers') as http:
        report = URLAnalyzer('https://example.com').analyze()
    http.assert_not_called()
    assert report['dns']['status'] == 'failed'
    assert report['coverage']['percent'] < 100
