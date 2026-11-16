"""Evaluate static triage rules against an explicit, locally supplied corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from engine import URLAnalyzer
from url_utils import defang_url


def evaluate(cases: list[dict], threshold: int = 30) -> dict:
    outcomes = []
    for case in cases:
        report = URLAnalyzer(case['url'], static_only=True).analyze()
        expected = case['expected_review']
        if not isinstance(expected, bool):
            raise ValueError('expected_review must be a JSON boolean')
        outcomes.append({
            'url': defang_url(case['url']), 'expected_review': expected,
            'predicted_review': report['risk_score'] >= threshold,
            'score': report['risk_score'], 'source': case.get('source', 'unspecified'),
        })
    tp = sum(row['expected_review'] and row['predicted_review'] for row in outcomes)
    fp = sum(not row['expected_review'] and row['predicted_review'] for row in outcomes)
    fn = sum(row['expected_review'] and not row['predicted_review'] for row in outcomes)
    tn = len(outcomes) - tp - fp - fn
    return {
        'mode': 'static-only', 'threshold': threshold, 'cases': len(outcomes),
        'true_positive': tp, 'false_positive': fp, 'false_negative': fn, 'true_negative': tn,
        'precision': tp / (tp + fp) if tp + fp else None,
        'recall': tp / (tp + fn) if tp + fn else None,
        'note': 'Bundled examples are synthetic triage expectations, not a validated phishing benchmark.',
        'outcomes': outcomes,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', nargs='?', type=Path, default=Path(__file__).parent / 'evaluation' / 'synthetic.json')
    parser.add_argument('--threshold', type=int, choices=range(0, 101), default=30, metavar='0..100')
    args = parser.parse_args()
    print(json.dumps(evaluate(json.loads(args.corpus.read_text()), args.threshold), indent=2))
