"""Bounded evidence selection. Complete records remain in evidence.json."""
import copy
import json
from collections import Counter, defaultdict, deque

from core.evidence import build_evidence


def serialize_dossier(dossier):
    return json.dumps(dossier, ensure_ascii=True, separators=(',', ':'))


def _spread(items, limit):
    """Evenly sample a sequence, including its beginning and end."""
    if len(items) <= limit:
        return items
    if limit == 1:
        return [items[-1]]
    return [items[round(i * (len(items) - 1) / (limit - 1))] for i in range(limit)]


def _preview(value, depth=0):
    changed = False
    if isinstance(value, str):
        return (value[:1600] + '…', True) if len(value) > 1600 else (value, False)
    if depth >= 8 and isinstance(value, (list, dict)):
        return {'preview_omitted': 'nested data; consult evidence.json'}, True
    if isinstance(value, dict):
        output = {}
        for key, item in list(value.items())[:30]:
            output[key], truncated = _preview(item, depth + 1)
            changed |= truncated
        return output, changed or len(value) > 30
    if isinstance(value, list):
        output = []
        for item in _spread(value, 20):
            child, truncated = _preview(item, depth + 1)
            output.append(child)
            changed |= truncated
        return output, changed or len(value) > 20
    return value, False


class ContextWindowMaximizer:
    def __init__(self, target_tokens=100000, chars_per_token=3.0, max_calls_per_proc=450):
        self.max_chars = int(target_tokens * chars_per_token)
        self.max_calls_per_proc = int(max_calls_per_proc)
        if self.max_chars < 4096 or self.max_calls_per_proc < 1:
            raise ValueError('Budget must allow 4096 characters and at least one call per process')

    def build_maximized_dossier(self, initial_static, unpacked_statics, cape_raw):
        return self.build_from_evidence(build_evidence(initial_static, unpacked_statics, cape_raw))

    def build_from_evidence(self, evidence):
        ordinary, by_process = [], defaultdict(list)
        for record in evidence['records']:
            if record['kind'] in ('api_call', 'emulated_api_call'):
                by_process[record['process_key']].append(record)
            else:
                ordinary.append(record)
        for calls in by_process.values():
            selected = []
            for priority in sorted({c['priority'] for c in calls}):
                pool = [c for c in calls if c['priority'] == priority]
                selected.extend(_spread(pool, self.max_calls_per_proc - len(selected)))
                if len(selected) >= self.max_calls_per_proc:
                    break
            ordinary.extend(selected)
        # Interleave record kinds and processes within a priority to avoid one busy process
        # monopolizing the dossier. Each call retains source order, timestamp and thread ID.
        groups = defaultdict(deque)
        for record in ordinary:
            groups[(record['priority'], record['kind'], record.get('process_key', ''))].append(record)
        candidates = []
        for priority in sorted({key[0] for key in groups}):
            queues = [groups[key] for key in sorted(groups) if key[0] == priority]
            while any(queues):
                for queue in queues:
                    if queue:
                        record = copy.deepcopy(queue.popleft())
                        record['data'], truncated = _preview(record['data'])
                        record['preview_truncated'] = truncated
                        if len(serialize_dossier(record)) > 16000:
                            record['data'] = {'preview_omitted': 'Large record; consult source or evidence.json'}
                            record['preview_truncated'] = True
                        candidates.append(record)
        coverage, coverage_truncated = _preview(evidence['coverage'])
        dossier = {'schema_version': 1, 'coverage': coverage,
                   'coverage_preview_truncated': coverage_truncated,
                   'selection': {'full_evidence': 'evidence.json',
                                 'total_records': len(evidence['records']),
                                 'total_by_kind': dict(Counter(r['kind'] for r in evidence['records'])),
                                 'character_ceiling': self.max_chars,
                                 'token_count_is_estimate': True,
                                 'max_api_calls_per_process': self.max_calls_per_proc,
                                 'order': 'Priority selection; reconstruct chronology using timestamp, process_key, sequence, thread_id. '
                                          'No cross-process causality is implied by timestamp alone.'},
                   'records': []}
        self._update_counts(dossier)
        used = len(serialize_dossier(dossier))
        for record in candidates:
            cost = len(serialize_dossier(record)) + 1
            if used + cost <= self.max_chars - 1024:
                dossier['records'].append(record)
                used += cost
        return self.shrink_dossier(dossier, self.max_chars)

    @staticmethod
    def _update_counts(dossier):
        selection = dossier['selection']
        selection['selected_records'] = len(dossier['records'])
        selection['omitted_records'] = selection['total_records'] - len(dossier['records'])
        counts = Counter(r['kind'] for r in dossier['records'])
        selection['omitted_by_kind'] = {kind: total - counts[kind]
                                        for kind, total in selection['total_by_kind'].items()
                                        if total > counts[kind]}
        selection['truncated_previews'] = sum(r.get('preview_truncated', False) for r in dossier['records'])

    @classmethod
    def shrink_dossier(cls, dossier, max_chars):
        if max_chars < 4096:
            raise ValueError('Token budget is too small for useful evidence')
        dossier = copy.deepcopy(dossier)
        dossier['selection']['character_ceiling'] = max_chars
        cls._update_counts(dossier)
        # Bulk-remove trailing (lowest priority) records, then check exact serialization.
        while len(serialize_dossier(dossier)) > max_chars and dossier['records']:
            excess = len(serialize_dossier(dossier)) - max_chars
            removed = 0
            while dossier['records'] and removed < excess + 128:
                removed += len(serialize_dossier(dossier['records'].pop())) + 1
            cls._update_counts(dossier)
        if len(serialize_dossier(dossier)) > max_chars:
            raise ValueError('Budget is too small for evidence coverage metadata')
        return dossier
