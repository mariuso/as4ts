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

test('rejects an invalid maximum', () => {
  assert.throws(() => new MessageBudget(Number.NaN), RangeError);
  assert.throws(() => new MessageBudget(Number.POSITIVE_INFINITY), RangeError);
  assert.throws(() => new MessageBudget(-1), RangeError);
  assert.throws(() => new MessageBudget(1.5), RangeError);
});

test('rejects an invalid reservation', () => {
  const budget = new MessageBudget(10);
  assert.throws(() => budget.reserve(Number.NaN), RangeError);
  assert.throws(() => budget.reserve(Number.POSITIVE_INFINITY), RangeError);
  assert.throws(() => budget.reserve(-1), RangeError);
  assert.equal(budget.remaining(), 10);
});

test('zero is a valid, already-exhausted budget', () => {
  const budget = new MessageBudget(0);
  assert.equal(budget.remaining(), 0);
  assert.equal(budget.reserve(1), false);
});
