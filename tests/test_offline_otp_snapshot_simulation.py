"""Offline thought-experiment tests; never import an app or real mail adapter.

All numbers are synthetic. The candidate rule sees only two code snapshots.
Ground truth belongs to the test fixture, not to that rule. No code is submitted.
"""
import argparse
import json
import socket
import time
import unittest
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch


@dataclass(frozen=True)
class Scenario:
    key: str
    label: str
    before: tuple[str, ...]
    after: tuple[str, ...]
    # Hidden ground truth used by the test oracle, not by candidate selection.
    current_code: str | None
    delivery_at: int | None
    expected: str
    explanation: str
    before_error: bool = False
    after_error: bool = False


SCENARIOS = (
    Scenario('normal', '新码在20秒到达', ('111111',), ('111111', '222222'),
             '222222', 20, 'correct_candidate', '完整快照、单次请求、接口及时刷新：差分选对候选。'),
    Scenario('near_deadline', '新码在59秒到达', ('111111',), ('111111', '222222'),
             '222222', 59, 'correct_candidate', '60秒读取时新码已经可见，差分选对候选。'),
    Scenario('empty_baseline', '发码前邮箱确实为空', (), ('222222',),
             '222222', 20, 'correct_candidate', '已知为空的快照与读取失败不是一回事。'),
    Scenario('leading_zero', '新码带前导零', ('111111',), ('111111', '001234'),
             '001234', 20, 'correct_candidate', '按字符串比较，前导零不丢失。'),
    Scenario('no_mail', '没有新邮件', ('111111',), ('111111',),
             None, None, 'no_new_mail', '没有新增候选，与设定的真实情况一致。'),
    Scenario('reorder', '完整历史列表仅重新排序', ('111111', '333333'), ('333333', '111111'),
             None, None, 'no_new_mail', '保存全部旧码再作差集，不会被排序变化骗过。'),
    Scenario('late_delivery', '本次邮件95秒才到达', ('111111',), ('111111',),
             '222222', 95, 'not_arrived_by_60s', '60秒时确实尚未到；不能由此判断发送失败。'),
    Scenario('cached_read', '邮件20秒到达但接口仍返回缓存', ('111111',), ('111111',),
             '222222', 20, 'missed_candidate', '邮件已到，但60秒响应没有反映它；无新增不等于没收到。'),
    Scenario('same_number', '新邮件再次使用相同数值', ('111111',), ('111111',),
             '111111', 20, 'missed_candidate', '假设服务端复用同一数值或发生碰撞；差集会排除这封新邮件。'),
    Scenario('incomplete_baseline', '快照漏了一封旧邮件', ('111111',), ('111111', '222222'),
             None, None, 'wrong_candidate', '222222在发码前已存在，但第一次接口没返回；会被误当作新增。'),
    Scenario('previous_request', '上一次请求的邮件晚到', ('111111',), ('111111', '222222'),
             '444444', 95, 'wrong_candidate', '222222来自上次请求；本次邮件95秒才到，60秒时会选错候选。'),
    Scenario('recipient_mixup', '接口混入其他收件人的邮件', ('111111',), ('111111', '222222'),
             None, None, 'wrong_candidate', '假设接口收件人过滤不正确；仅比较数值无法辨别归属。'),
    Scenario('multiple_new', '60秒内出现两个不同新增码', ('111111',), ('111111', '333333', '222222'),
             '222222', 30, 'ambiguous', '差集有两个候选；未约定接口排序时，不能仅凭列表位置确定最新。'),
    Scenario('baseline_error', '发码前快照读取失败', (), ('222222',),
             '222222', 20, 'baseline_error', '快照失败应单独报告，不能当作“邮箱为空”。', before_error=True),
    Scenario('read_error', '60秒后的读取失败', ('111111',), (),
             '222222', 20, 'read_error', '读取失败不能当作“没有新邮件”。', after_error=True),
)


class VirtualClock:
    def __init__(self):
        self.seconds = -1

    def advance_to(self, seconds):
        if seconds < self.seconds:
            raise ValueError('virtual time cannot move backwards')
        self.seconds = seconds


class FixtureMailbox:
    """Fixed fixture responses only; deliberately no URL/client configuration."""
    def __init__(self, scenario, clock):
        self.scenario = scenario
        self.clock = clock
        self.reads = []

    def read(self):
        self.reads.append(self.clock.seconds)
        if self.clock.seconds < 0:
            if self.scenario.before_error:
                raise OSError('synthetic baseline read failure')
            return tuple(self.scenario.before)
        if self.clock.seconds != 60:
            raise AssertionError('the post-send fixture must be read at virtual second 60')
        if self.scenario.after_error:
            raise OSError('synthetic post-send read failure')
        return tuple(self.scenario.after)


def simulate(scenario):
    """One offline cycle; no resend, real mail read, or verification submission."""
    clock = VirtualClock()
    mailbox = FixtureMailbox(scenario, clock)
    result = {'case': scenario.key, 'label': scenario.label,
              'before': list(scenario.before), 'after_60s': list(scenario.after),
              'candidate': None, 'new_candidates': [], 'send_recorded': False,
              'explanation': scenario.explanation}
    try:
        baseline = frozenset(mailbox.read())
    except OSError:
        result.update(outcome='baseline_error', elapsed_seconds=None, read_times=mailbox.reads)
        return result
    clock.advance_to(0)  # A virtual send marker only: no real sending function.
    result['send_recorded'] = True
    clock.advance_to(60)
    try:
        after = mailbox.read()
    except OSError:
        result.update(outcome='read_error', elapsed_seconds=60, read_times=mailbox.reads)
        return result

    # The exact snapshot-difference rule under discussion. No metadata is used.
    new = sorted(set(after) - baseline)
    result['new_candidates'] = new
    if len(new) > 1:
        outcome = 'ambiguous'
    elif len(new) == 1:
        result['candidate'] = new[0]
        # The oracle below knows which mail belongs to this virtual request.
        outcome = 'correct_candidate' if (
            new[0] == scenario.current_code
            and scenario.delivery_at is not None and scenario.delivery_at <= 60
        ) else 'wrong_candidate'
    elif scenario.delivery_at is not None and scenario.delivery_at <= 60:
        outcome = 'missed_candidate'
    elif scenario.delivery_at is not None:
        outcome = 'not_arrived_by_60s'
    else:
        outcome = 'no_new_mail'
    result.update(outcome=outcome, elapsed_seconds=60, read_times=mailbox.reads)
    return result


class OfflineSnapshotSimulationTests(unittest.TestCase):
    def test_all_fixed_cases_have_the_expected_outcome(self):
        for scenario in SCENARIOS:
            with self.subTest(case=scenario.key):
                self.assertEqual(simulate(scenario)['outcome'], scenario.expected)

    def test_successful_baseline_always_waits_60_virtual_seconds(self):
        for scenario in SCENARIOS:
            result = simulate(scenario)
            if not scenario.before_error:
                self.assertEqual(result['elapsed_seconds'], 60)
                self.assertEqual(result['read_times'], [-1, 60])

    def test_baseline_failure_does_not_become_an_empty_baseline(self):
        result = simulate(next(s for s in SCENARIOS if s.key == 'baseline_error'))
        self.assertFalse(result['send_recorded'])
        self.assertEqual(result['read_times'], [-1])
        self.assertIsNone(result['candidate'])

    def test_unchanged_response_can_mean_different_things(self):
        cases = [next(s for s in SCENARIOS if s.key == key)
                 for key in ('no_mail', 'cached_read', 'same_number', 'late_delivery')]
        self.assertEqual(len({(s.before, s.after) for s in cases}), 1)
        # Cache staleness and a repeated value are different causes but both
        # produce the same observable result: no candidate despite delivery.
        self.assertEqual(len({simulate(s)['outcome'] for s in cases}), 3)

    def test_one_new_number_can_be_current_or_old(self):
        cases = [next(s for s in SCENARIOS if s.key == key)
                 for key in ('normal', 'incomplete_baseline', 'previous_request')]
        self.assertEqual(len({(s.before, s.after) for s in cases}), 1)
        self.assertEqual([len(simulate(s)['new_candidates']) for s in cases], [1, 1, 1])
        self.assertEqual([simulate(s)['outcome'] for s in cases],
                         ['correct_candidate', 'wrong_candidate', 'wrong_candidate'])

    def test_multiple_candidates_are_not_silently_treated_as_latest(self):
        result = simulate(next(s for s in SCENARIOS if s.key == 'multiple_new'))
        self.assertEqual(len(result['new_candidates']), 2)
        self.assertIsNone(result['candidate'])

    def test_leading_zero_is_preserved(self):
        self.assertEqual(simulate(next(s for s in SCENARIOS if s.key == 'leading_zero'))['candidate'], '001234')

    def test_simulation_is_deterministic(self):
        self.assertEqual([simulate(s) for s in SCENARIOS], [simulate(s) for s in SCENARIOS])


LABELS = {'correct_candidate': '正确候选', 'no_new_mail': '无新增，与设定一致',
          'not_arrived_by_60s': '60秒时尚未到达', 'missed_candidate': '漏判：邮件已到但未选出',
          'wrong_candidate': '误选：不是本次邮件', 'ambiguous': '多个新增，无法唯一确定',
          'baseline_error': '快照读取失败', 'read_error': '后续读取失败'}


def write_report(folder, results, elapsed):
    folder.mkdir(parents=True, exist_ok=True)
    counts = Counter(row['outcome'] for row in results)
    data = {'offline_only': True, 'virtual_wait_seconds': 60,
            'wall_time_seconds': round(elapsed, 6), 'real_mail_reads': 0,
            'real_sends': 0, 'verification_submissions': 0,
            'case_count': len(results), 'counts': dict(counts), 'results': results}
    (folder / 'results.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# 发码前快照 + 60秒后差分：离线模拟结果', '',
             '全部数据为虚构夹具；60秒为虚拟时钟，未读取真实邮箱、未发码、未提交验证码，也未修改生产策略。', '',
             '## 方法', '',
             '虚拟时间 -1 秒读取已有验证码集合；0 秒记录模拟发码；60 秒读取第二份集合；排除旧集合。',
             '单个新增只记作候选；多个新增单独报告歧义，不假设接口列表排序。测试另持有隐藏的真实归属来判断是否选对。', '',
             '## 逐例结果', '', '| 场景 | 结果 | 说明 |', '|---|---|---|']
    lines.extend(f"| {r['label']} | {LABELS[r['outcome']]} | {r['explanation']} |" for r in results)
    lines.extend(['', '## 结论与边界', '',
                  '- 在完整快照、正确收件人、没有历史请求晚到、接口及时刷新、唯一新增码的设定下，差分方法选对候选。',
                  '- 相同的两份验证码集合可对应不同真实情况；数值差分本身不能区分这些情况。',
                  '- 未变化不一定没收到；新增也不一定来自本次请求。60秒是本次测试参数，不是从真实收件速度统计得到的阈值。',
                  '- 邮件时间/ID是额外证据，不是万能保证；前次请求晚到和同邮箱并发还涉及请求归属。',
                  '- 这些反例是构造的边界测试，不说明你的供应商实际存在这些问题；案例占比不能当作真实错误率。',
                  '- 本次没有测试真实邮件延迟、验证码有效期、补发或线上重试成功率，没有把结果接入注册器。', '',
                  f'共 {len(results)} 个固定场景；8 项单元测试通过，实际执行耗时约 {elapsed:.4f} 秒。', '',
                  '## 复现', '', '```powershell',
                  '& "D:\\MY_PROJECT\\AutoCodex\\any-auto-register\\.venv\\Scripts\\python.exe" "D:\\MY_PROJECT\\AutoCodex\\any-auto-register\\tests\\test_offline_otp_snapshot_simulation.py" --report-dir "D:\\MY_PROJECT\\AutoCodex\\any-auto-register\\run\\diagnostics\\otp-snapshot-simulation-20261027"',
                  '```', '',
                  '首次执行有一项测试断言把4种真实原因误写为4种输出分类；缓存未刷新与相同数值都属于漏判，实际是3种分类。已仅修正该断言，候选规则未改变。初次日志保留在 test-run-initial.log。'])
    (folder / 'RESULTS.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Synthetic, offline-only snapshot comparison tests')
    parser.add_argument('--report-dir', type=Path)
    args = parser.parse_args()
    started = time.perf_counter()
    # Any accidental socket connection during this experiment fails the run.
    with patch.object(socket.socket, 'connect', side_effect=AssertionError('Offline simulation forbids network')), \
         patch.object(socket, 'create_connection', side_effect=AssertionError('Offline simulation forbids network')):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OfflineSnapshotSimulationTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        results = [simulate(s) for s in SCENARIOS]
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.report_dir:
        data = write_report(args.report_dir, results, time.perf_counter() - started)
        print(json.dumps({key: data[key] for key in ('offline_only', 'case_count', 'counts', 'real_sends', 'verification_submissions')}, ensure_ascii=False))
