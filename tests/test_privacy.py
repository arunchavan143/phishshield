from url_utils import defang_url, redact_report


def test_redacted_copy_covers_redirects_and_embedded_evidence_urls():
    original = {'subject': {'url': 'https://example.com/login?token=SECRET#FRAGMENT'}, 'evidence': [{'detail': 'Target https://example.com?code=OTHER'}]}
    result = redact_report(original)
    assert 'SECRET' not in str(result)
    assert 'FRAGMENT' not in str(result)
    assert 'OTHER' not in str(result)
    assert 'SECRET' in original['subject']['url']
    assert defang_url('https://example.com?token=SECRET') == 'hxxps://example[.]com?token=REDACTED'


def test_relative_location_query_is_redacted():
    assert 'SECRET' not in str(redact_report({'location': '/login?token=SECRET#FRAGMENT'}))
