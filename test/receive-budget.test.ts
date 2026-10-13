import test from 'node:test';
import assert from 'node:assert/strict';
import { MessageBudget } from '../src/receive/budget.js';

test('reserves aggregate output and refuses to exceed the budget', () => {
  const budget = new MessageBudget(100);
  assert.equal(budget.remaining(), 100);
  assert.equal(budget.reserve(40), true);
  assert.equal(budget.remaining(), 60);
  assert.equal(budget.reserve(60), true);
  assert.equal(budget.remaining(), 0);
  assert.equal(budget.reserve(1), false, 'exhausted budget refuses more');
  assert.equal(budget.remaining(), 0);
});

test('a refused reservation records nothing', () => {
  const budget = new MessageBudget(10);
  assert.equal(budget.reserve(11), false);
  assert.equal(budget.remaining(), 10);
});

test('rejects non-finite and negative reservations', () => {
  const budget = new MessageBudget(10);
  assert.equal(budget.reserve(Number.NaN), false);
  assert.equal(budget.reserve(Number.POSITIVE_INFINITY), false);
  assert.equal(budget.reserve(-1), false);
  assert.equal(budget.remaining(), 10);
});
