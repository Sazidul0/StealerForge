"""Syntax and bounded fixture checks, not a production-readiness certification."""
import re
from pathlib import Path

import plyara
import yara
import yaml
from sigma.collection import SigmaCollection


class AutomatedRuleValidator:
    def __init__(self, yara_timeout_seconds=30):
        self.timeout = yara_timeout_seconds

    @staticmethod
    def _blocks(markdown):
        # A closing fence must occupy its own line. Ignore ordinary prose and unrelated code.
        return re.findall(r'^```(yara|yar|yaml|yml|sigma)[ \t]*\r?\n(.*?)^```[ \t]*$',
                          markdown, re.MULTILINE | re.DOTALL | re.IGNORECASE)

    def extract_and_validate(self, markdown_report, test_binaries, output_dir, benign_binaries=None):
        results = {'status': 'no_rules', 'yara_validation': [], 'sigma_validation': [],
                   'production_ready': False,
                   'limitations': ['Sigma backend conversion and event replay are not performed',
                                   'Fixture matches do not establish family coverage or population false-positive rate']}
        output_dir = Path(output_dir)
        benign_binaries = benign_binaries or []
        for language, block in self._blocks(markdown_report):
            if language.lower() in ('yara', 'yar'):
                index = len(results['yara_validation']) + 1
                path = output_dir / f'generated_rule_{index}.yar'
                path.write_text(block.strip() + '\n', encoding='utf-8')
                result = {'file': path.name, 'passed': False, 'compiled_successfully': False,
                          'positive_hits': {}, 'benign_hits': {}, 'benign_tested': bool(benign_binaries)}
                results['yara_validation'].append(result)
                try:
                    compiled = yara.compile(source=block, includes=False)
                    result['compiled_successfully'] = True
                    parsed = plyara.Plyara().parse_string(block)
                    public_rules = {rule['rule_name'] for rule in parsed if 'private' not in rule.get('scopes', [])}
                    if not public_rules:
                        raise ValueError('No public YARA detection rules found')
                    matched = set()
                    for paths, target in [(test_binaries, 'positive_hits'), (benign_binaries, 'benign_hits')]:
                        for binary in paths:
                            binary = Path(binary)
                            if not binary.is_file():
                                raise ValueError(f'Test artifact missing: {binary.name}')
                            hits = [m.rule for m in compiled.match(filepath=str(binary), timeout=self.timeout)]
                            result[target][str(binary)] = hits
                            if target == 'positive_hits':
                                matched.update(hits)
                    result['unmatched_rules'] = sorted(public_rules - matched)
                    result['passed'] = bool(test_binaries) and not result['unmatched_rules'] and not any(result['benign_hits'].values())
                    result['assessment'] = 'fixture_checks_passed' if result['passed'] else 'fixture_checks_failed'
                except Exception as exc:
                    result['error'] = str(exc)
            else:
                index = len(results['sigma_validation']) + 1
                path = output_dir / f'generated_sigma_{index}.yml'
                path.write_text(block.strip() + '\n', encoding='utf-8')
                result = {'file': path.name, 'passed': False, 'backend_tested': False}
                results['sigma_validation'].append(result)
                try:
                    docs = list(yaml.safe_load_all(block))
                    if not docs or any(not isinstance(doc, dict) for doc in docs):
                        raise ValueError('Sigma block must contain YAML rule mappings')
                    collection = SigmaCollection.from_yaml(block)
                    if not collection.rules:
                        raise ValueError('No Sigma rules found')
                    titles = []
                    for rule in collection.rules:
                        detection = getattr(rule, 'detection', None)
                        if detection is None:
                            raise ValueError('Correlation rules need a separate backend validation workflow')
                        # Condition parsing is lazy; force it to reject undefined selection names.
                        for condition in detection.parsed_condition:
                            _ = condition.parsed
                        titles.append(rule.title)
                    result.update(passed=True, assessment='syntax_valid_only', titles=titles)
                except Exception as exc:
                    result['error'] = str(exc)
        checks = results['yara_validation'] + results['sigma_validation']
        if checks:
            results['status'] = 'checks_passed' if all(r['passed'] for r in checks) else 'checks_failed'
        return results
