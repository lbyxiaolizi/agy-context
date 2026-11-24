import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeTranscript } from './context-analyzer.mjs';

test('analyzeTranscript records per-turn cache_hit_ratio and cumulative avgCacheHitRatio', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-context-analyzer-'));
  const transcriptPath = path.join(dir, 'transcript.jsonl');
  const entries = [
    { step_index: 0, type: 'USER_INPUT', content: 'Hello', created_at: '2026-11-24T00:00:00Z' },
    { step_index: 1, type: 'PLANNER_RESPONSE', input_tokens: 10000, cache_read_tokens: 0, output_tokens: 200, content: 'Hi', created_at: '2026-11-24T00:00:05Z' },
    { step_index: 2, type: 'USER_INPUT', content: 'Check cache', created_at: '2026-11-24T00:00:10Z' },
    { step_index: 3, type: 'PLANNER_RESPONSE', input_tokens: 3000, cache_read_tokens: 12000, output_tokens: 300, content: 'Done', created_at: '2026-11-24T00:00:15Z' },
    { step_index: 4, type: 'USER_INPUT', content: 'Next turn', created_at: '2026-11-24T00:00:20Z' },
    { step_index: 5, type: 'PLANNER_RESPONSE', input_tokens: 10000, cache_read_tokens: 10000, output_tokens: 100, content: 'Half', created_at: '2026-11-24T00:00:25Z' },
    { step_index: 6, type: 'PLANNER_RESPONSE', input_tokens: 0, cache_read_tokens: 0, output_tokens: 0, content: '', created_at: '2026-11-24T00:00:30Z' }
  ];
  fs.writeFileSync(transcriptPath, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');

  try {
    const result = await analyzeTranscript(transcriptPath, { conversationId: 'test-conv-cache' });
    assert.equal(result.timeline.length, 4);
    assert.deepEqual(
      result.timeline.map(t => ({ turn: t.turn, total: t.total_context, ratio: t.cache_hit_ratio })),
      [
        { turn: 1, total: 10000, ratio: 0 },
        { turn: 2, total: 15000, ratio: 80 },
        { turn: 3, total: 20000, ratio: 50 },
        { turn: 4, total: 0, ratio: 0 }
      ]
    );
    assert.equal(result.overview.cacheHitRatio, 0);
    assert.equal(result.overview.avgCacheHitRatio, 48.9);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
