"""PR Radar 面向用户的中文说明。

内部状态码保持稳定，供数据库和脚本使用；命令行与报告输出通过本模块补充
中文主说明，避免用户必须猜测英文缩写和蛇形状态码。
"""

from __future__ import annotations

from typing import Any

CODE_MESSAGES_ZH = {
    "post_audit_tier_a_evidence_not_found": "旧版兼容状态：当时尚未生成独立的任务完成后审核结论",
    "post_audit_tier_a_not_met": "独立的任务完成后审核已结束，但结论未达到允许发布的等级",
    "policy_migration_requires_revalidation": "规则已经升级，旧审核结果需要按新规则重新验证",
    "contract_health_failed": "自动化审核链完整性检查失败，已暂停公开发布",
    "local_fix_not_ready": "本地修复尚未达到可交付状态",
    "publication_request_not_persisted": "发布申请未能写入记录库",
    "publication_request_pending": "本地修复和测试证据已登记，正在立即执行发布前安全检查",
    "publication_request_waiting_for_post_audit": "旧版兼容状态：当时尚未完成任务后审核",
    "publication_prediction_not_eligible": "没有找到符合当前规则的发布前预测记录",
    "post_audit_not_approved": "独立的任务完成后审核未通过，不能发布",
    "local_fix_evidence_not_ready": "本地修复或测试证据尚未准备完整",
    "publication_request_approved": "发布申请已经批准",
    "publication_request_rejected": "发布申请已经拒绝",
    "publication_request_binding_required": "发布申请缺少任务、规则或代码版本绑定",
    "publication_request_binding_mismatch": "发布申请与任务、分支或代码版本不一致",
    "publication_request_not_pending": "发布申请已经被处理，不能重复签发许可",
    "invalid_commit_sha": "提交版本号格式不正确",
    "worktree_not_found": "找不到本地代码工作区",
    "worktree_git_state_unreadable": "无法读取本地代码工作区的版本状态",
    "commit_sha_drift": "当前代码版本已经变化，与申请时不一致",
    "branch_unavailable": "当前分支不可用或处于游离状态",
    "task_not_found": "找不到对应的自动化任务",
    "evidence_digest_mismatch": "证据摘要与登记记录不一致",
    "decision_contract_digest_mismatch": "审核规则指纹已经变化，需要重新审核",
    "opportunity_not_registered": "该问题尚未登记到候选任务库",
    "policy_unknown": "无法确认仓库的贡献政策",
    "normal": "普通代码贡献流程",
    "legal_confirmation": "需要用户亲自完成法律确认的贡献流程",
    "INTERNAL_AUDIT_READINESS_NOT_MET": "内部审核样本和准确率尚未达到启用标准",
    "LIVE_WIP_REFRESH_FAILED": "旧版兼容状态：当时全量刷新无关拉取请求失败",
    "WORKTREE_NOT_CLEAN": "本地代码工作区包含未提交改动",
    "LIVE_GATE_UNAVAILABLE": "无法完成 GitHub 实时状态检查",
    "REPOSITORY_POLICY_UNAVAILABLE": "无法读取仓库贡献政策",
    "REQUEST_ALREADY_CLAIMED": "该发布申请已经被其他审核进程领取",
    "POST_ISSUE_LIVENESS_FAILED": "签发许可后发现任务或分支状态已经失效",
    "REGISTRY_AUTHORIZATION_FAILED": "无法把发布授权安全写入任务登记表",
    "THREAD_WAKE_FAILED": "无法唤醒原任务继续发布流程",
    "APPROVED": "已批准",
    "REJECTED": "已拒绝",
    "RETRY": "等待条件恢复后重试",
    "PENDING": "等待审核",
    "SKIPPED": "已跳过",
    "PASS": "通过",
    "FAILED": "失败",
    "OPEN": "进行中",
    "FROZEN": "样本已经冻结",
    "GO": "审核通过，可以继续",
    "NO_GO": "审核未通过，不应继续发布",
    "UNKNOWN": "信息不足，暂时无法判断",
    "LOCAL_FIX_READY": "本地修复与交付材料已经准备好",
    "PR_OPEN": "拉取请求已经创建",
    "BUILD_AND_HOLD": "可以完成本地修复，但暂不公开发布",
    "TIER_A": "最高优先级候选",
    "WATCH": "继续观察，暂不实施",
    "DROP": "放弃该候选",
    "policy_revalidation": "规则升级后重新审核",
    "POLICY_REVALIDATION_COMPLETE": "已经按当前规则完成重新审核",
    "POLICY_REVALIDATION_ALREADY_COMPLETE": "此前已经按当前规则完成重新审核，无需重复执行",
    "POLICY_REVALIDATION_NOT_TIER_A": "按当前规则重新评估后，未达到最高优先级",
    "POLICY_REVALIDATION_SNAPSHOT_MISSING": "缺少可供重新审核的原始候选快照",
    "REGISTRY_TASK_IDENTITY_MISSING": "任务登记信息与当前问题或线程不一致",
    "INDEPENDENT_TASK_OUTCOME_NOT_MATURE": "独立的任务完成后审核尚未结束",
    "AWAITING_POST_AUDIT": "旧版兼容状态：当时尚未完成任务后审核",
    "AWAITING_BROKER": "本地修复和测试证据已就绪，正在立即执行发布前安全检查",
    "POST_AUDIT_NOT_APPROVED": "独立的任务完成后审核未通过，发布申请已拒绝",
    "LOCAL_FIX_EVIDENCE_NOT_READY": "本地修复或测试证据与发布申请不一致",
    "validated_local_fix_policy": "本地修复与测试完成后自动发布",
    "RELEASE_STABILITY_NOT_MET": "新版规则的稳定观察期尚未达到要求",
    "WORKTREE_UNREADABLE": "无法读取本地代码工作区",
    "COMMIT_SHA_DRIFT": "当前代码版本与审核时登记的版本不一致",
    "prospective_calibration": "事前盲审校准组",
    "prospective_holdout": "事前盲审保留验证组",
    "prospective_operational": "事前盲审正式运行组",
}

TOKEN_MESSAGES_ZH = {
    "policy": "规则",
    "migration": "升级",
    "requires": "需要",
    "revalidation": "重新验证",
    "publication": "发布",
    "request": "申请",
    "evidence": "证据",
    "not": "未",
    "found": "找到",
    "failed": "失败",
    "missing": "缺失",
    "invalid": "无效",
    "mismatch": "不一致",
    "unavailable": "不可用",
    "pending": "等待处理",
    "approved": "已批准",
    "rejected": "已拒绝",
    "ready": "已准备好",
    "internal": "内部",
    "external": "外部",
    "audit": "审核",
    "live": "实时",
    "gate": "安全门",
    "worktree": "代码工作区",
    "commit": "代码版本",
    "branch": "分支",
    "task": "任务",
    "contract": "审核规则",
    "digest": "指纹",
    "status": "状态",
    "unknown": "未知",
}


def describe_code_zh(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "未提供具体说明"
    if text in CODE_MESSAGES_ZH:
        return CODE_MESSAGES_ZH[text]
    upper = text.upper()
    if upper in CODE_MESSAGES_ZH:
        return CODE_MESSAGES_ZH[upper]
    words = [word for word in text.replace("-", "_").replace(":", "_").split("_") if word]
    translated = [TOKEN_MESSAGES_ZH.get(word.casefold(), word) for word in words]
    if translated and all(part != word for part, word in zip(translated, words, strict=True)):
        return "".join(translated)
    return "未能识别的内部状态；详细代码已保留供程序排错"


def add_chinese_explanations(value: Any) -> Any:
    if isinstance(value, list):
        return [add_chinese_explanations(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: add_chinese_explanations(item) for key, item in value.items()}
    reason = value.get("reason") or value.get("reasonCode") or value.get("reason_code")
    status = value.get("status")
    if reason:
        result.setdefault("原因说明", describe_code_zh(reason))
    if status:
        result.setdefault("状态说明", describe_code_zh(status))
    if "ok" in value:
        result.setdefault("处理结果", "成功" if value.get("ok") is True else "未成功")
    return result
