from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from engine import URLAnalyzer


APP = Path(__file__).resolve().parents[1] / 'app.py'


def sample_report():
    report = URLAnalyzer('https://example.com/login?token=SECRET', static_only=True).analyze()
    report['dns'] = {'status': 'complete', 'addresses': ['93.184.216.34'], 'error': None}
    return report


def test_report_survives_enrichment_and_notes_reruns():
    report = sample_report()
    at = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not at.exception
    with patch('engine.URLAnalyzer.analyze', return_value=report) as analyze:
        at.text_input[0].set_value(report['subject']['url'])
        at.button[0].click().run()
        assert not at.exception
        assert len(at.session_state['cases']) == 1
        assert 'SECRET' not in at.json[0].value
        with patch('intelligence.ip_info', return_value={'ip': '93.184.216.34', 'org': 'Example'}) as enrich:
            next(button for button in at.button if button.label == 'Enrich first resolved IP').click().run()
            assert not at.exception
            enrich.assert_called_once()
        at.text_area[0].set_value('Independent verification pending').run()
        assert not at.exception
        analyze.assert_called_once()
    saved = at.session_state['cases'][report['case_id']]
    assert saved['analyst']['notes'] == 'Independent verification pending'
    assert saved['enrichment']['org'] == 'Example'
    assert len(at.tabs) == 5


def test_session_history_retains_notes_when_switching_cases():
    first = sample_report()
    second = sample_report()
    at = AppTest.from_file(str(APP), default_timeout=15).run()
    with patch('engine.URLAnalyzer.analyze', side_effect=[first, second]) as analyze:
        at.text_input[0].set_value(first['subject']['url'])
        at.button[0].click().run()
        at.text_area[0].set_value('First case note').run()
        at.button[0].click().run()
        assert len(at.session_state['cases']) == 2
        next(box for box in at.selectbox if box.label == 'Session investigations').select(first['case_id']).run()
        assert not at.exception
        assert at.text_area[0].value == 'First case note'
        assert analyze.call_count == 2
