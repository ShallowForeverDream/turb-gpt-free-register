const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../webui/templates/job_log_script.html'), 'utf8');

function harness() {
  const elements = new Map();
  const pending = [];
  const copied = [];
  const downloads = [];
  const blobs = [];
  const intervals = new Map();
  const revoked = [];
  const timeouts = [];
  let sequence = 0;
  const $ = selector => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: '', disabled: false, checked: true, scrollTop: 0, clientHeight: 100, scrollHeight: 500,
      handlers: {}, classList: {remove() {}},
      addEventListener(event, fn) { this.handlers[event] = fn; },
    });
    return elements.get(selector);
  };
  const context = vm.createContext({
    $, activeLogJob: null, logTimer: null, Blob,
    updateModalScrollLock() {},
    api(url) { return new Promise((resolve, reject) => pending.push({url, resolve, reject})); },
    copyText(text) { copied.push(text); },
    setInterval(fn) { intervals.set(++sequence, fn); return sequence; },
    clearInterval(id) { intervals.delete(id); },
    setTimeout(fn) { timeouts.push(fn); },
    URL: {createObjectURL(blob) { blobs.push(blob); return 'blob:test'; }, revokeObjectURL(url) { revoked.push(url); }},
    document: {
      body: {appendChild() {}},
      createElement() { return {click() { downloads.push(this.download); }, remove() {}}; },
    },
  });
  vm.runInContext(source, context);
  return {context, $, pending, copied, downloads, blobs, intervals, revoked, timeouts};
}

const flush = () => new Promise(resolve => setImmediate(resolve));

test('copy and download the displayed log, preserving Unicode and line breaks', async () => {
  const h = harness();
  h.context.openLog(42);
  assert.equal(h.$('#btnCopyJobLog').disabled, true);
  h.pending[0].resolve({log: '第一行\nsecond line\n', job: {status: 'success'}});
  await flush();
  h.$('#btnCopyJobLog').handlers.click();
  h.$('#btnDownloadJobLog').handlers.click();
  assert.deepEqual(h.copied, ['第一行\nsecond line\n']);
  assert.equal(await h.blobs[0].text(), h.copied[0]);
  assert.deepEqual(h.downloads, ['job-42.log']);
  assert.equal(h.intervals.size, 0);
  h.timeouts.forEach(fn => fn());
  assert.deepEqual(h.revoked, ['blob:test']);
});

test('empty logs cannot be copied or downloaded', async () => {
  const h = harness();
  h.context.openLog(1);
  h.pending[0].resolve({log: '', job: {status: 'running'}});
  await flush();
  assert.equal(h.$('#btnCopyJobLog').disabled, true);
  assert.equal(h.$('#btnDownloadJobLog').disabled, true);
  h.$('#btnDownloadJobLog').handlers.click();
  assert.equal(h.blobs.length, 0);
});

test('late response from a previous task cannot overwrite the current task', async () => {
  const h = harness();
  h.context.openLog(1);
  h.context.openLog(2);
  h.pending[1].resolve({log: 'current', job: {status: 'running'}});
  await flush();
  h.pending[0].resolve({log: 'stale', job: {status: 'success'}});
  await flush();
  assert.equal(h.$('#logContent').textContent, 'current');
  assert.equal(h.intervals.size, 1);
});

test('closing and reopening the same task also discards stale responses', async () => {
  const h = harness();
  h.context.openLog(1);
  h.context.activeLogJob = null;
  h.context.openLog(1);
  h.pending[0].resolve({log: 'stale'});
  await flush();
  assert.equal(h.$('#logContent').textContent, '加载中…');
  h.pending[1].resolve({log: 'new'});
  await flush();
  assert.equal(h.$('#logContent').textContent, 'new');
});

test('scrolling up pauses following; rechecking resumes at the bottom', async () => {
  const h = harness();
  h.context.openLog(1);
  h.pending[0].resolve({log: 'first'});
  await flush();
  h.$('#logContent').scrollTop = 40;
  h.$('#logContent').handlers.scroll();
  assert.equal(h.$('#jobLogFollow').checked, false);
  const polling = h.context.pollLog();
  h.pending[1].resolve({log: 'first\nsecond'});
  await polling;
  assert.equal(h.$('#logContent').scrollTop, 40);
  h.$('#jobLogFollow').checked = true;
  h.$('#jobLogFollow').handlers.change();
  assert.equal(h.$('#logContent').scrollTop, 500);
});

test('polls do not overlap and failures preserve the displayed log', async () => {
  const h = harness();
  h.context.openLog(1);
  await h.context.pollLog();
  assert.equal(h.pending.length, 1);
  h.pending[0].resolve({log: 'keep this'});
  await flush();
  const polling = h.context.pollLog();
  h.pending[1].reject(new Error('HTTP 401'));
  await polling;
  assert.equal(h.$('#logContent').textContent, 'keep this');
  assert.match(h.$('#jobLogStatus').textContent, /HTTP 401/);
});
