from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from fractions import Fraction
from hashlib import sha256
from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    AuditLog,
    AuditResult,
    File,
    KnowledgeEntry,
    KnowledgeEntryPublicationStatus,
    OkfConversionJob,
    OkfConversionStatus,
)
from app.schemas.knowledge_bases import KnowledgeSearchHit
from app.services.attendance_query_plan import (
    AttendanceAggregateDimension,
    AttendanceAggregateMode,
    AttendanceAggregateSelection,
    AttendanceAggregationPlan,
    AttendanceQueryPlanParseResult,
    AttendanceQueryPlanStatus,
    parse_attendance_query_plan,
)

_MAX_ENTRIES: Final = 20
_MAX_TOTAL_CHARACTERS: Final = 8_000_000
_MAX_ROWS: Final = 100_000
_MAX_SOURCE_PATH_CHARACTERS: Final = 1_000
_MAX_TABLE_ROWS: Final = 50
_MAX_CELL_CHARACTERS: Final = 1_000
_MAX_LABEL_CHARACTERS: Final = 100
_MAX_EVIDENCE_CHARACTERS: Final = 100_000
_MAX_EXCEL_ROW: Final = 1_048_576
_MAX_EXCEL_COLUMN: Final = 16_384
_MAX_METADATA_LOCATIONS: Final = 2_048
_SOURCE_PARSERS: Final = ("ooxml-xlsx", "libreoffice-ooxml-xlsx")
SPREADSHEET_REJECTION_MESSAGE: Final = "当前表格证据不足或存在歧义，无法安全计算答案。"
_CELL_PATTERN: Final = re.compile(
    r"\[worksheet:(?P<sheet>[^\]\r\n]{1,31})!"
    r"(?P<column>[A-Za-z]{1,3})(?P<row>[1-9]\d{0,6})\]\s*"
)
_LOCATION_PATTERN: Final = re.compile(
    r"worksheet:(?P<sheet>[^\]\r\n]{1,31})!"
    r"(?P<column>[A-Za-z]{1,3})(?P<row>[1-9]\d{0,6})"
)
_SHEET_LOCATION_PATTERN: Final = re.compile(r"worksheet:[^\]\r\n]{1,31}")
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_QUOTED_TERM_PATTERN: Final = re.compile(r"[“\"'‘]([^”\"'’]{1,50})[”\"'’]")
_EVENT_RESULT_QUERY_TERMS: Final = (
    "认证失败",
    "黑名单拦截",
    "白名单拦截",
    "验证失败",
    "通行失败",
    "刷卡失败",
    "拒绝通行",
    "认证异常",
    "验证异常",
    "认证成功",
    "验证成功",
    "通行成功",
    "允许通行",
    "黑名单",
    "白名单",
    "异常",
)
_EVENT_RESULT_QUERY_ALIASES: Final = (
    ("认证不通过", "认证失败"),
    ("认证未通过", "认证失败"),
    ("验证不通过", "验证失败"),
    ("验证未通过", "验证失败"),
    ("无法通行", "通行失败"),
)
_EVENT_RESULT_TERM_MARKERS: Final = (
    "失败",
    "拦截",
    "拒绝",
    "成功",
    "通过",
    "允许",
    "禁止",
    "异常",
    "黑名单",
    "白名单",
    "超时",
)
_EVENT_RESULT_POLICY_TERMS: Final = (
    "制度",
    "条款",
    "政策",
    "规范",
    "流程",
    "办法",
    "手册",
)
_EVENT_RESULT_SEGMENT_PATTERN: Final = re.compile(r"[\s()（）/|,，;；:：\-]+")
_SPREADSHEET_FILENAME_PATTERN: Final = re.compile(r"\.(?:xlsx?|csv)\Z", re.IGNORECASE)
_SPREADSHEET_REFERENCE_PATTERN: Final = re.compile(
    r"[^\s，。？！?\"'“”‘’]{1,200}\.(?:xlsx?|csv)", re.IGNORECASE
)
_CITATION_LIKE_PATTERN: Final = re.compile(r"\[\s*-?\d+\s*\]")
_SPREADSHEET_REFERENCE_PREFIXES: Final = tuple(
    sorted(
        (
            "请打开",
            "请查看",
            "查询",
            "根据",
            "基于",
            "参照",
            "请查询",
            "请读取",
            "打开",
            "查看",
            "查询",
            "读取",
            "使用",
            "关于",
            "工作簿",
            "文件",
            "这份",
            "该份",
            "在",
            "从",
        ),
        key=len,
        reverse=True,
    )
)
_EVENT_RESULT_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "是否出现过",
            "是否发生过",
            "是否存在",
            "是否包含",
            "有没有",
            "是否有",
            "考勤记录",
            "考勤数据",
            "打卡记录",
            "打卡数据",
            "通行记录",
            "门禁记录",
            "事件记录",
            "异常记录",
            "出现过",
            "发生过",
            "这份",
            "该份",
            "当前",
            "本次",
            "这张",
            "该张",
            "考勤表",
            "考勤明细",
            "考勤",
            "工作表",
            "工作簿",
            "帮我查一下",
            "请帮我",
            "请问",
            "有无",
            "存在",
            "包含",
            "出现",
            "发生",
            "或者",
            "以及",
            "记录",
            "数据",
            "打卡",
            "考勤",
            "通行",
            "门禁",
            "事件",
            "结果",
            "状态",
            "表格",
            "文件",
            "核验",
            "检查",
            "确认",
            "查询",
            "是否",
            "中的",
            "里面",
            "当中",
            "请",
            "在",
            "中",
            "里",
            "内",
            "有",
            "或",
            "和",
            "与",
            "的",
            "吗",
            "么",
            "呢",
        ),
        key=len,
        reverse=True,
    )
)
_EVENT_RESULT_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_DEVICE_FREQUENCY_ATTENDANCE_TERMS: Final = (
    "打卡",
    "考勤",
    "刷卡",
    "门禁记录",
    "通行记录",
    "门禁设备",
    "闸机设备",
    "考勤设备",
)
_DEVICE_FREQUENCY_DEVICE_TERMS: Final = (
    "闸机设备",
    "门禁设备",
    "考勤设备",
    "打卡设备",
    "闸机",
    "门禁机",
    "考勤机",
    "设备名称",
    "设备",
)
_DEVICE_FREQUENCY_AGGREGATE_TERMS: Final = (
    "使用频率最高",
    "使用最频繁",
    "使用得最频繁",
    "出现次数最多",
    "打卡次数最多",
    "打卡次数最高",
    "打卡量最大",
    "打卡量最多",
    "记录次数最多",
    "记录最多",
    "次数最多",
    "使用最多",
    "频率最高",
    "频次最高",
    "最常使用",
    "最常用",
    "记录最少",
    "次数最少",
    "使用最少",
    "频率最低",
    "频次最低",
    "最不常用",
    "最频繁",
    "打卡最多",
    "考勤最多",
    "通行最多",
    "排行榜",
    "排行",
    "排名",
    "top",
    "分别有多少",
    "各有多少",
    "每台",
)
_DEVICE_FREQUENCY_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "在所有闸机设备中",
            "所有闸机设备中",
            "所有闸机设备",
            "哪台门禁设备",
            "哪台闸机",
            "哪个闸机",
            "哪一个考勤设备",
            "打卡记录最多",
            "打卡次数最多",
            "打卡最多",
            "考勤记录最多",
            "通行记录最多",
            "记录次数最多",
            "出现次数最多",
            "使用频率最高",
            "使用最频繁",
            "使用得最频繁",
            "打卡次数最高",
            "打卡量最大",
            "打卡量最多",
            "频率最高",
            "频次最高",
            "使用最多",
            "最常使用",
            "最常用",
            "请汇总",
            "汇总",
            "以及次数",
            "以及",
            "共记录了多少次",
            "共记录多少次",
            "一共记录了多少次",
            "一共记录多少次",
            "一共多少次",
            "共计多少次",
            "总共多少次",
            "共多少次",
            "共几次",
            "有几次",
            "有多少次",
            "多少次",
            "是哪一个",
            "是哪一台",
            "是哪台",
            "是哪个",
            "是什么",
            "哪个设备",
            "哪个",
            "哪台设备",
            "设备名称",
            "闸机设备",
            "门禁设备",
            "考勤设备",
            "打卡设备",
            "打卡记录",
            "考勤记录",
            "刷卡记录",
            "通行记录",
            "门禁记录",
            "记录",
            "打卡",
            "考勤",
            "刷卡",
            "设备",
            "闸机",
            "门禁机",
            "考勤机",
            "所有",
            "全部",
            "这份",
            "其中",
            "请问",
            "请",
            "在",
            "中",
            "里",
            "的",
            "了",
            "共",
        ),
        key=len,
        reverse=True,
    )
)
_DEVICE_FREQUENCY_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_EMPLOYEE_FREQUENCY_ATTENDANCE_TERMS: Final = (
    "打卡",
    "考勤",
    "刷卡",
    "门禁记录",
    "通行记录",
)
_EMPLOYEE_FREQUENCY_EMPLOYEE_TERMS: Final = (
    "哪位员工",
    "哪名员工",
    "哪个员工",
    "每位员工",
    "每名员工",
    "每个员工",
    "员工",
    "人员",
    "谁",
)
_EMPLOYEE_FREQUENCY_REQUEST_TERMS: Final = (
    "打卡总次数最多",
    "打卡次数最多",
    "考勤次数最多",
    "刷卡次数最多",
    "打卡记录最多",
    "考勤记录最多",
    "记录次数最多",
    "出现次数最多",
    "打卡最多",
    "考勤最多",
    "次数最多",
    "频次最高",
    "频率最高",
    "打卡次数最高",
    "考勤次数最高",
    "打卡量最大",
    "考勤量最大",
    "最频繁",
    "打卡次数最少",
    "考勤次数最少",
    "记录最少",
    "次数最少",
    "每位员工",
    "每名员工",
    "每个员工",
)
_EMPLOYEE_FREQUENCY_UNSUPPORTED_TERMS: Final = (
    "最少",
    "最低",
    "排行榜",
    "排行",
    "排名",
    "每位员工",
    "每名员工",
    "每个员工",
    "分别",
    "占比",
    "比例",
    "趋势",
    "分组",
)
_EMPLOYEE_FREQUENCY_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "整个数据集中",
            "整个数据集里",
            "整个数据集",
            "全部数据中",
            "全部数据里",
            "全体员工中",
            "所有员工中",
            "这份考勤数据中",
            "这份考勤记录中",
            "这份考勤数据",
            "这份考勤记录",
            "打卡总次数最多",
            "打卡次数最多",
            "考勤次数最多",
            "刷卡次数最多",
            "打卡记录最多",
            "考勤记录最多",
            "记录次数最多",
            "出现次数最多",
            "打卡最多",
            "考勤最多",
            "次数最多",
            "频次最高",
            "频率最高",
            "打卡次数最高",
            "考勤次数最高",
            "打卡量最大",
            "考勤量最大",
            "最频繁",
            "总共打卡了多少次",
            "总共打卡多少次",
            "一共打卡了多少次",
            "一共打卡多少次",
            "共打卡了多少次",
            "共打卡多少次",
            "总共记录了多少次",
            "总共记录多少次",
            "一共记录了多少次",
            "一共记录多少次",
            "总共多少次",
            "一共多少次",
            "共多少次",
            "有几次",
            "次数是多少",
            "是哪一位员工",
            "是哪位员工",
            "是哪名员工",
            "是哪个员工",
            "哪一位员工",
            "哪位员工",
            "哪名员工",
            "哪个员工",
            "员工是谁",
            "人员是谁",
            "谁",
            "打卡记录",
            "考勤记录",
            "刷卡记录",
            "门禁记录",
            "通行记录",
            "打卡",
            "考勤",
            "刷卡",
            "员工",
            "人员",
            "全部",
            "所有",
            "其中",
            "请问",
            "请",
            "总共",
            "一共",
            "共",
            "是",
            "的",
            "了",
            "在",
            "中",
            "里",
        ),
        key=len,
        reverse=True,
    )
)
_EMPLOYEE_FREQUENCY_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_EMPLOYEE_FREQUENCY_TOP_N_PATTERN: Final = re.compile(
    r"(?:前\s*\d+|top\s*\d+)",
    flags=re.IGNORECASE,
)
_MISSING_DEVICE_LABELS: Final = frozenset(
    (
        "-",
        "--",
        "—",
        "n/a",
        "#n/a",
        "na",
        "nan",
        "null",
        "none",
        "unknown",
        "未知",
        "无",
        "不详",
        "未填写",
        "未设置",
        "未分配",
    )
)
_DEPARTMENT_SUMMARY_ATTENDANCE_TERMS: Final = (
    "考勤记录",
    "考勤数据",
    "考勤表",
    "考勤明细",
    "打卡记录",
    "打卡数据",
    "打卡表",
    "门禁记录",
    "通行记录",
    "考勤",
    "打卡",
)
_DEPARTMENT_SUMMARY_REQUEST_TERMS: Final = (
    "多少个不同",
    "几个不同",
    "多少个部门",
    "几个部门",
    "哪些部门",
    "部门有哪些",
    "所有部门",
    "全部部门",
    "部门名称",
    "部门名单",
    "部门清单",
    "部门列表",
    "每个部门",
    "各部门",
    "部门排名",
    "部门排行",
    "部门总数",
    "部门数量",
    "部门种类",
    "部门分布",
    "多少种",
    "几种",
    "去重",
    "汇总",
    "统计",
)
_DEPARTMENT_SUMMARY_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "请列出这些部门的名称",
            "请列出部门名称",
            "请列出名称",
            "请全部列出",
            "请查看",
            "查询",
            "根据",
            "基于",
            "参照",
            "请汇总",
            "请说明",
            "请解释",
            "告诉我",
            "说明",
            "解释",
            "员工考勤记录",
            "人员考勤记录",
            "员工考勤数据",
            "人员考勤数据",
            "部门去重后有多少",
            "部门总数是多少",
            "部门数量和名称是什么",
            "包含多少种部门",
            "多少种不同部门",
            "多少种部门",
            "几种不同部门",
            "几种部门",
            "部门种类有哪些",
            "多少个组织部门",
            "多少个独立部门",
            "几个组织部门",
            "几个独立部门",
            "包含哪些部门名称",
            "多少个部门",
            "几个部门",
            "分别是什么",
            "分别叫什么",
            "多少个不同的部门",
            "多少个不同部门",
            "几个不同的部门",
            "几个不同部门",
            "所有部门有哪些",
            "全部部门有哪些",
            "有哪些部门",
            "部门有哪些",
            "请列出",
            "一共包含了",
            "一共包含",
            "总共包含了",
            "总共包含",
            "考勤记录",
            "考勤数据",
            "考勤表",
            "考勤明细",
            "考勤",
            "打卡记录",
            "打卡数据",
            "打卡表",
            "门禁记录",
            "通行记录",
            "部门名称",
            "部门名单",
            "部门清单",
            "部门列表",
            "部门总数",
            "部门数量",
            "部门种类",
            "组织部门",
            "所属部门",
            "独立部门",
            "所有部门",
            "全部部门",
            "去重后有多少",
            "去重后",
            "去重",
            "汇总",
            "统计",
            "是多少",
            "是什么",
            "分别",
            "和名称",
            "名称",
            "数量",
            "并",
            "哪些",
            "不同",
            "叫什么",
            "都",
            "多少种",
            "几种",
            "多少",
            "几个",
            "涉及的",
            "涉及",
            "这份",
            "该份",
            "当前",
            "请问",
            "麻烦",
            "帮我",
            "列出",
            "部门",
            "一共",
            "总共",
            "共有",
            "包含",
            "里有",
            "中有",
            "中的",
            "中",
            "里",
            "内",
            "请",
            "的",
            "了",
            "有",
        ),
        key=len,
        reverse=True,
    )
)
_DEPARTMENT_SUMMARY_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_DEPARTMENT_SUMMARY_UNSUPPORTED_TERMS: Final = (
    "每个部门",
    "各部门",
    "多少人",
    "几个人",
    "人数",
    "姓名",
    "工号",
    "卡号",
    "排名",
    "排行",
    "top",
    "排除",
    "剔除",
    "不包括",
    "除了",
    "设备",
    "闸机",
    "门禁机",
    "考勤机",
    "认证",
    "验证",
    "成功",
    "失败",
    "异常",
    "黑名单",
    "白名单",
    "次数",
    "频率",
    "占比",
    "比例",
    "分布",
    "分组",
)
_DEPARTMENT_SUMMARY_PROSE_TERMS: Final = (
    "制度",
    "流程",
    "规范",
    "定义",
    "职责",
    "政策",
    "手册",
    "部门说明",
    "字段说明",
    "数据说明",
)
_DEPARTMENT_RECORD_COUNT_ATTENDANCE_TERMS: Final = (
    "打卡记录",
    "考勤记录",
    "刷卡记录",
    "门禁记录",
    "通行记录",
    "打卡",
    "考勤",
    "刷卡",
    "门禁",
    "通行",
)
_DEPARTMENT_RECORD_COUNT_REQUEST_TERMS: Final = (
    "一共有多少条",
    "共有多少条",
    "共计多少条",
    "总共多少条",
    "有多少条",
    "多少条",
    "一共有几条",
    "共有几条",
    "共计几条",
    "总共几条",
    "有几条",
    "几条",
    "打卡次数",
    "考勤次数",
    "刷卡次数",
    "门禁次数",
    "通行次数",
    "记录数",
    "总数",
    "数量",
    "合计",
    "总量",
    "累计",
    "有多少",
    "多少次",
    "几次",
)
_DEPARTMENT_RECORD_COUNT_NEUTRAL_PHRASES: Final = tuple(
    sorted(
        (
            "在这段时间内",
            "在该时间段内",
            "这段时间内",
            "该时间段内",
            "在这段时间",
            "在该时间段",
            "这段时间",
            "该时间段",
            "一共有多少条",
            "共有多少条",
            "共计多少条",
            "总共多少条",
            "有多少条",
            "多少条",
            "一共有几条",
            "共有几条",
            "共计几条",
            "总共几条",
            "有几条",
            "几条",
            "一共记录了多少次",
            "一共记录多少次",
            "共记录了多少次",
            "共记录多少次",
            "共打卡多少次",
            "共打卡了多少次",
            "共计多少次",
            "总共多少次",
            "有多少次",
            "多少次",
            "有几次",
            "几次",
            "打卡记录",
            "考勤记录",
            "刷卡记录",
            "门禁记录",
            "通行记录",
            "打卡次数",
            "考勤次数",
            "刷卡次数",
            "门禁次数",
            "通行次数",
            "记录数",
            "总数是多少",
            "总数",
            "数量是多少",
            "数量",
            "合计是多少",
            "合计",
            "总量是多少",
            "总量",
            "有多少",
            "总计",
            "累计",
            "请统计",
            "帮我统计",
            "统计一下",
            "统计",
            "帮我算一下",
            "算一下",
            "请问一下",
            "问一下",
            "能否",
            "可以",
            "帮忙",
            "麻烦",
            "一下",
            "请问",
            "请",
            "一共",
            "总共",
            "共计",
            "共有",
            "打卡",
            "考勤",
            "刷卡",
            "门禁",
            "通行",
            "记录",
            "次数",
            "了",
            "的",
            "有",
            "吗",
            "呢",
            "么",
        ),
        key=len,
        reverse=True,
    )
)
_DEPARTMENT_RECORD_COUNT_UNSUPPORTED_TERMS: Final = (
    "今天",
    "昨日",
    "昨天",
    "前天",
    "本周",
    "上周",
    "本月",
    "上月",
    "今年",
    "去年",
    "上午",
    "下午",
    "设备",
    "闸机",
    "考勤机",
    "认证",
    "验证",
    "成功",
    "失败",
    "异常",
    "黑名单",
    "白名单",
    "每位员工",
    "每个员工",
    "每名员工",
    "分别",
    "姓名",
    "工号",
    "卡号",
    "每个部门",
    "各部门",
    "排名",
    "排行",
    "top",
    "占比",
    "比例",
    "分布",
    "分组",
    "排除",
    "剔除",
    "不包括",
    "除了",
)
_DEPARTMENT_RECORD_COUNT_RESIDUAL_PATTERN: Final = re.compile(
    r"[\s,，。？！?!、；;：:/\"'“”‘’()（）《》【】\[\]]+"
)
_MISSING_SPREADSHEET_VALUE_LABELS: Final = frozenset(
    (
        *_MISSING_DEVICE_LABELS,
        "#ref!",
        "#value!",
        "#div/0!",
        "#name?",
        "#num!",
        "#null!",
        "#spill!",
        "#calc!",
    )
)
_MISSING_DEPARTMENT_LABELS: Final = _MISSING_SPREADSHEET_VALUE_LABELS

_HEADER_ALIASES: Final[dict[str, dict[str, int]]] = {
    "employee_id": {
        "人员工号": 0,
        "员工工号": 0,
        "工号": 1,
        "人员编号": 1,
        "员工编号": 1,
    },
    "card_number": {
        "卡号": 0,
        "门禁卡号": 0,
        "考勤卡号": 0,
        "卡片编号": 1,
    },
    "employee_name": {
        "姓名": 0,
        "员工姓名": 0,
        "人员姓名": 0,
    },
    "department": {
        "部门": 0,
        "部门名称": 0,
        "所属部门": 0,
        "组织部门": 1,
    },
    "timestamp": {
        "时间": 0,
        "打卡时间": 0,
        "考勤时间": 0,
        "通行时间": 0,
        "记录时间": 1,
        "事件时间": 1,
        "刷卡时间": 1,
    },
    "device": {
        "设备": 0,
        "设备名称": 0,
        "闸机": 0,
        "闸机名称": 0,
        "门禁闸机名称": 0,
        "通行设备": 0,
        "打卡设备": 0,
        "考勤设备": 0,
        "门禁设备": 0,
        "出入口名称": 1,
        "通道名称": 1,
        "门名称": 1,
        "考勤点": 2,
        "位置": 2,
    },
    "event_type": {
        "事件类型": 0,
        "消息类型": 1,
        "事件类别": 1,
    },
    "event_result": {
        "事件结果": 0,
        "事件详情": 0,
        "认证结果": 0,
        "验证结果": 0,
        "通行结果": 0,
        "刷卡结果": 0,
        "处理结果": 1,
        "结果": 2,
    },
}


@dataclass(frozen=True, slots=True)
class SpreadsheetTable:
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    citation_numbers: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SpreadsheetAnswer:
    answer: str
    table: SpreadsheetTable | None
    hits: tuple[KnowledgeSearchHit, ...]


class SpreadsheetQueryStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    REJECTED = "rejected"
    ANSWERED = "answered"


@dataclass(frozen=True, slots=True)
class SpreadsheetQueryResult:
    status: SpreadsheetQueryStatus
    answer: SpreadsheetAnswer | None
    rejection_message: str | None = None

    @property
    def applicable(self) -> bool:
        return self.status is not SpreadsheetQueryStatus.NOT_APPLICABLE


@dataclass(frozen=True, slots=True)
class _EntrySource:
    id: UUID
    source_file_id: UUID | None
    title: str
    source_path: str | None
    format_version: str | None
    source_text: str
    source_locations: tuple[str, ...]
    source_location_count: int | None
    locations_truncated: bool
    source_text_sha256: str
    source_locations_sha256: str | None
    integrity_metadata: bool


@dataclass(frozen=True, slots=True)
class _Cell:
    column: str
    value: str


@dataclass(frozen=True, slots=True)
class _Row:
    entry: _EntrySource
    sheet: str
    number: int
    cells: tuple[_Cell, ...]

    def value(self, column: str | None) -> str | None:
        if column is None:
            return None
        return next((cell.value for cell in self.cells if cell.column == column), None)

    @property
    def excerpt(self) -> str:
        return " ".join(
            f"[worksheet:{self.sheet}!{cell.column}{self.number}] {cell.value}"
            for cell in self.cells
        )


@dataclass(frozen=True, slots=True)
class _Sheet:
    rows: tuple[_Row, ...]
    columns: dict[str, str | None]
    ambiguous: frozenset[str]
    multiple_attendance_headers: bool


@dataclass(frozen=True, slots=True)
class _Record:
    row: _Row
    sheet: _Sheet
    timestamp: datetime | None = None


@dataclass(frozen=True, slots=True)
class _EventResultCoverage:
    entry: _EntrySource
    sheet: str
    column: str
    first_row: int
    last_row: int
    scanned_rows: int
    counts: tuple[tuple[str, int], ...]
    matched_rows: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _DeviceFrequencyCoverage:
    entry: _EntrySource
    sheet: str
    column: str
    first_row: int
    last_row: int
    scanned_rows: int
    counts: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True, slots=True)
class _EmployeeFrequencyCoverage:
    entry: _EntrySource
    sheet: str
    identifier_column: str
    name_column: str
    timestamp_column: str
    first_row: int
    last_row: int
    scanned_rows: int
    counts: tuple[tuple[str, str, str, int], ...]


@dataclass(frozen=True, slots=True)
class _DepartmentSummaryCoverage:
    entry: _EntrySource
    sheet: str
    column: str
    first_row: int
    last_row: int
    scanned_rows: int
    departments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _DepartmentRecordCountCoverage:
    entry: _EntrySource
    sheet: str
    department_column: str
    timestamp_column: str
    first_row: int
    last_row: int
    scanned_rows: int
    matched_rows: int


@dataclass(frozen=True, slots=True)
class _AttendanceAggregateRecord:
    row: _Row
    timestamp: datetime
    employee_key: str | None
    employee_identifier: str | None
    employee_name: str | None
    department_key: str | None
    department_label: str | None
    device_key: str
    device_label: str
    event_type_key: str | None
    event_type_label: str | None
    event_result_key: str | None
    event_result_label: str | None


@dataclass(frozen=True, slots=True)
class _AttendanceAggregateCoverage:
    entry: _EntrySource
    sheet: str
    columns: tuple[str, ...]
    first_row: int
    last_row: int
    scanned_rows: int
    matched_rows: int


@dataclass(frozen=True, slots=True)
class _AttendanceAggregateFilters:
    employee_keys: frozenset[str] = frozenset()
    department_keys: frozenset[str] = frozenset()
    device_keys: frozenset[str] = frozenset()
    event_type_keys: frozenset[str] = frozenset()
    event_result_terms: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        return bool(
            self.employee_keys
            or self.department_keys
            or self.device_keys
            or self.event_type_keys
            or self.event_result_terms
        )


@dataclass(frozen=True, slots=True)
class _QuestionIntent:
    aggregate_parse: AttendanceQueryPlanParseResult
    latest_record: bool
    earliest_record: bool
    time_range: bool
    employee_field: str | None
    department_employees: bool
    department_record_count: bool
    department_summary: bool
    event_result_existence: bool
    employee_frequency: bool
    device_frequency: bool

    @property
    def applicable(self) -> bool:
        return any(
            (
                self.latest_record,
                self.earliest_record,
                self.aggregate_parse.applicable,
                self.time_range,
                self.employee_field,
                self.department_employees,
                self.department_record_count,
                self.department_summary,
                self.event_result_existence,
                self.employee_frequency,
                self.device_frequency,
            )
        )


def is_spreadsheet_query_intent(question: str) -> bool:
    """Return whether a question must stay inside the fail-closed table path."""

    normalized = unicodedata.normalize("NFKC", question).strip()
    return bool(normalized and _question_intent(normalized).applicable)


async def evaluate_spreadsheet_query(
    session: AsyncSession,
    knowledge_base_id: UUID,
    question: str,
) -> SpreadsheetQueryResult:
    """Evaluate table intent without allowing unsafe cases to fall through to RAG."""

    if not is_spreadsheet_query_intent(question):
        return SpreadsheetQueryResult(status=SpreadsheetQueryStatus.NOT_APPLICABLE, answer=None)
    answer = await answer_spreadsheet_query(session, knowledge_base_id, question)
    if answer is None:
        return SpreadsheetQueryResult(
            status=SpreadsheetQueryStatus.REJECTED,
            answer=None,
            rejection_message=SPREADSHEET_REJECTION_MESSAGE,
        )
    return SpreadsheetQueryResult(status=SpreadsheetQueryStatus.ANSWERED, answer=answer)


async def answer_spreadsheet_query(
    session: AsyncSession,
    knowledge_base_id: UUID,
    question: str,
) -> SpreadsheetAnswer | None:
    """Answer supported spreadsheet questions from published XLSX evidence only."""

    normalized_question = unicodedata.normalize("NFKC", question).strip()
    if not normalized_question:
        return None
    intent = _question_intent(normalized_question)
    if not intent.applicable:
        return None
    sources = await _load_sources(session, knowledge_base_id)
    if sources is None:
        return None
    sources = _select_sources(sources, normalized_question)
    if sources is None:
        return None
    sheets = _reconstruct_sheets(sources)
    if (
        not sheets
        or any(sheet.multiple_attendance_headers for sheet in sheets)
        or any(
            sheet.rows and not _valid_coverage_sheet_name(sheet.rows[0].sheet) for sheet in sheets
        )
    ):
        return None

    aggregate_parse = intent.aggregate_parse
    if (
        aggregate_parse.status is AttendanceQueryPlanStatus.COMPILED
        and _has_cross_sheet_duplicate_attendance_rows(sheets)
    ):
        return None
    if intent.department_employees and (
        aggregate_parse.plan is None
        or (
            aggregate_parse.plan.date_range is None
            and aggregate_parse.plan.mode is not AttendanceAggregateMode.DEPARTMENT_PROFILE
        )
    ):
        return _answer_department_employees(sheets, normalized_question)
    if intent.department_record_count and _question_date(normalized_question) is None:
        if not _all_source_sheets_reconstructed(sources, sheets):
            return None
        legacy_department_count = _answer_department_record_count(
            sheets,
            _strip_selected_source_filename_mentions(normalized_question, sources),
        )
        if legacy_department_count is not None:
            return legacy_department_count
    if (
        aggregate_parse.status is AttendanceQueryPlanStatus.COMPILED
        and aggregate_parse.plan is not None
        and _should_use_generic_attendance_aggregate(
            aggregate_parse.plan,
            normalized_question,
        )
    ):
        if not _all_source_sheets_reconstructed(sources, sheets):
            return None
        return _answer_attendance_aggregate(
            sheets,
            aggregate_parse.plan,
            normalized_question,
        )

    if intent.employee_frequency:
        if not _all_source_sheets_reconstructed(sources, sheets):
            return None
        return _answer_employee_frequency(sheets, normalized_question)
    if intent.device_frequency:
        if not _all_source_sheets_reconstructed(sources, sheets):
            return None
        return _answer_device_frequency(sheets, normalized_question)
    if intent.department_record_count:
        if not _all_source_sheets_reconstructed(sources, sheets):
            return None
        return _answer_department_record_count(
            sheets,
            _strip_selected_source_filename_mentions(normalized_question, sources),
        )
    if intent.department_summary:
        return _answer_department_summary(
            sheets,
            _strip_selected_source_filename_mentions(normalized_question, sources),
        )
    if intent.event_result_existence:
        return _answer_event_result_existence(sheets, normalized_question)
    if intent.earliest_record:
        return _answer_earliest_record(sheets, normalized_question)
    if intent.latest_record:
        return _answer_latest_record(sheets, normalized_question)
    if intent.time_range:
        return _answer_time_range(sheets, normalized_question)
    if intent.employee_field == "employee_id":
        return _answer_employee_field(
            sheets,
            normalized_question,
            field="employee_id",
            field_label="人员工号",
        )
    if intent.employee_field == "card_number":
        return _answer_employee_field(
            sheets,
            normalized_question,
            field="card_number",
            field_label="卡号",
        )
    if intent.department_employees:
        return _answer_department_employees(sheets, normalized_question)
    if aggregate_parse.status is AttendanceQueryPlanStatus.REJECTED:
        return None
    return None


def _question_intent(question: str) -> _QuestionIntent:
    aggregate_parse = parse_attendance_query_plan(question)
    employee_lookup = _has_employee_field_lookup_shape(question)
    asks_employee_id = employee_lookup and "工号" in question
    asks_card_number = employee_lookup and "卡号" in question
    employee_field = (
        "ambiguous"
        if asks_employee_id and asks_card_number
        else "employee_id"
        if asks_employee_id
        else "card_number"
        if asks_card_number
        else None
    )
    employee_list_request = any(
        token in question for token in ("哪几位", "有谁", "哪些", "名单", "多少位", "总共有")
    ) or (
        any(token in question for token in ("列出", "列举"))
        and re.search(r"部门.{0,4}(?:员工|人员)", question) is not None
    )
    department_employee_scope = (
        re.search(
            r"部(?:门)?.{0,12}(?:员工|人员)",
            question,
        )
        is not None
    )
    department_employees = department_employee_scope and employee_list_request
    time_range = _is_time_range_question(question)
    latest_record = _is_latest_record_question(question) and not time_range
    earliest_record = _is_earliest_record_question(question) and not time_range
    department_summary = _is_department_summary_question(question) and not department_employees
    event_result_existence = _is_event_result_existence_question(question)
    employee_frequency = _is_employee_frequency_question(question)
    device_frequency = _is_device_frequency_question(question)
    department_record_count = (
        _is_department_record_count_question(question)
        and not department_employees
        and not department_summary
        and not event_result_existence
        and not employee_frequency
        and not device_frequency
        and not latest_record
        and not earliest_record
        and not time_range
    )
    return _QuestionIntent(
        aggregate_parse=aggregate_parse,
        latest_record=latest_record,
        earliest_record=earliest_record,
        time_range=time_range,
        employee_field=employee_field,
        department_employees=department_employees,
        department_record_count=department_record_count,
        department_summary=department_summary,
        event_result_existence=event_result_existence,
        employee_frequency=employee_frequency,
        device_frequency=device_frequency,
    )


def _has_employee_field_lookup_shape(question: str) -> bool:
    if not any(token in question for token in ("多少", "什么", "是", "为", "查询", "分别")):
        return False
    if re.search(r"[“\"][^”\"]{1,50}[”\"]\s*的", question):
        return True
    if re.search(
        r"(?:员工|人员)\s*[“\"]?[A-Za-z0-9一-鿿·_-]{2,40}[”\"]?\s*的",
        question,
    ):
        return True
    generic_subjects = {"公司", "本公司", "企业", "部门", "项目", "系统", "平台", "员工", "人员"}
    subjects = re.findall(r"([A-Za-z0-9一-鿿·_-]{2,40})的", question)
    return any(subject not in generic_subjects for subject in subjects)


def _is_department_summary_question(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    if any(term in semantic_question for term in _DEPARTMENT_SUMMARY_PROSE_TERMS):
        return False
    attendance_context = any(
        term in semantic_question for term in _DEPARTMENT_SUMMARY_ATTENDANCE_TERMS
    )
    department_context = "部门" in semantic_question
    summary_request = any(
        term in semantic_question for term in _DEPARTMENT_SUMMARY_REQUEST_TERMS
    ) or any(term in semantic_question for term in ("多少", "几个", "哪些", "叫什么"))
    list_request = (
        re.search(
            r"(?:列出|列举).{0,24}部门|部门.{0,24}(?:列出|列举)",
            semantic_question,
        )
        is not None
    )
    return attendance_context and department_context and (summary_request or list_request)


def _is_department_record_count_question(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    attendance_context = any(
        term in semantic_question for term in _DEPARTMENT_RECORD_COUNT_ATTENDANCE_TERMS
    )
    count_request = any(
        term in semantic_question for term in _DEPARTMENT_RECORD_COUNT_REQUEST_TERMS
    )
    return attendance_context and count_request


def _has_unsupported_department_record_count_scope(
    question: str,
    department: str,
) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    department_key = unicodedata.normalize("NFKC", department).casefold()
    semantic_question = semantic_question.replace(department_key, "")
    if _question_date(semantic_question) is not None:
        return True
    if any(term in semantic_question for term in _DEPARTMENT_RECORD_COUNT_UNSUPPORTED_TERMS):
        return True
    residual = semantic_question
    for phrase in _DEPARTMENT_RECORD_COUNT_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_DEPARTMENT_RECORD_COUNT_RESIDUAL_PATTERN.sub("", residual))


def _has_unsupported_department_summary_scope(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    if _question_date(semantic_question) is not None:
        return True
    if any(term in semantic_question for term in _DEPARTMENT_SUMMARY_UNSUPPORTED_TERMS):
        return True
    residual = semantic_question
    for phrase in _DEPARTMENT_SUMMARY_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_DEPARTMENT_SUMMARY_RESIDUAL_PATTERN.sub("", residual))


def _is_employee_frequency_question(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    attendance_context = any(
        term in semantic_question for term in _EMPLOYEE_FREQUENCY_ATTENDANCE_TERMS
    )
    employee_context = any(term in semantic_question for term in _EMPLOYEE_FREQUENCY_EMPLOYEE_TERMS)
    aggregate_request = any(term in semantic_question for term in _EMPLOYEE_FREQUENCY_REQUEST_TERMS)
    return attendance_context and employee_context and aggregate_request


def _has_unsupported_employee_frequency_scope(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    if _question_date(semantic_question) is not None:
        return True
    if any(term in semantic_question for term in _EMPLOYEE_FREQUENCY_UNSUPPORTED_TERMS):
        return True
    if _EMPLOYEE_FREQUENCY_TOP_N_PATTERN.search(semantic_question):
        return True
    residual = semantic_question
    for phrase in _EMPLOYEE_FREQUENCY_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_EMPLOYEE_FREQUENCY_RESIDUAL_PATTERN.sub("", residual))


def _is_device_frequency_question(question: str) -> bool:
    semantic_question = _strip_spreadsheet_filename_mentions(question).casefold()
    attendance_context = any(
        term in semantic_question for term in _DEVICE_FREQUENCY_ATTENDANCE_TERMS
    )
    device_context = any(term in semantic_question for term in _DEVICE_FREQUENCY_DEVICE_TERMS)
    aggregate_request = any(term in semantic_question for term in _DEVICE_FREQUENCY_AGGREGATE_TERMS)
    attendance_device_context = any(
        term in semantic_question for term in ("闸机", "门禁机", "考勤机")
    )
    return (
        (attendance_context or attendance_device_context) and device_context and aggregate_request
    )


def _has_unsupported_device_frequency_scope(question: str) -> bool:
    residual = _strip_spreadsheet_filename_mentions(question)
    for phrase in _DEVICE_FREQUENCY_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_DEVICE_FREQUENCY_RESIDUAL_PATTERN.sub("", residual))


def _is_event_result_existence_question(question: str) -> bool:
    has_spreadsheet_reference = _has_spreadsheet_filename_mention(question)
    semantic_question = _normalize_event_result_query_aliases(
        _strip_spreadsheet_filename_mentions(question)
    )
    if any(token in semantic_question for token in _EVENT_RESULT_POLICY_TERMS):
        return False
    existence_query = any(
        token in semantic_question
        for token in (
            "有没有",
            "是否有",
            "有无",
            "是否存在",
            "是否包含",
            "是否出现",
            "是否发生",
            "出现过",
            "发生过",
        )
    ) or bool(
        re.search(
            r"(?:记录|数据).{0,12}(?:里|中)?(?:有|存在|包含|出现|发生).{0,40}[吗么?？]",
            semantic_question,
        )
        or re.search(
            r"(?:有|存在|包含|出现|发生).{0,40}(?:记录|事件).{0,3}[吗么?？]",
            semantic_question,
        )
    )
    attendance_records = any(
        token in semantic_question
        for token in ("考勤", "打卡", "通行记录", "门禁记录", "考勤数据", "打卡数据")
    ) or (has_spreadsheet_reference and "记录" in semantic_question)
    result_condition = bool(_event_result_terms(semantic_question)) or any(
        token in semantic_question
        for token in ("事件结果", "认证结果", "验证结果", "通行结果", "刷卡结果")
    )
    return existence_query and attendance_records and result_condition


def _strip_spreadsheet_filename_mentions(question: str) -> str:
    without_quoted_files = _QUOTED_TERM_PATTERN.sub(_quoted_filename_replacement, question)
    return _SPREADSHEET_REFERENCE_PATTERN.sub("", without_quoted_files)


def _normalize_event_result_query_aliases(question: str) -> str:
    normalized = unicodedata.normalize("NFKC", question)
    for alias, canonical in _EVENT_RESULT_QUERY_ALIASES:
        normalized = normalized.replace(alias, canonical)
    return normalized


def _has_spreadsheet_filename_mention(question: str) -> bool:
    return bool(_mentioned_spreadsheet_filename_candidates(question))


def _mentioned_spreadsheet_filename_candidates(
    question: str,
) -> tuple[frozenset[str], ...]:
    normalized = unicodedata.normalize("NFKC", question)
    mentions: list[frozenset[str]] = []
    for match in _SPREADSHEET_REFERENCE_PATTERN.finditer(normalized):
        raw_name = re.split(r"[/\\]", match.group(0))[-1].strip().casefold()
        candidates = {raw_name}
        candidate = raw_name
        stripped_prefix = True
        while stripped_prefix:
            stripped_prefix = False
            for prefix in _SPREADSHEET_REFERENCE_PREFIXES:
                normalized_prefix = unicodedata.normalize("NFKC", prefix).casefold()
                if candidate.startswith(normalized_prefix) and len(candidate) > len(
                    normalized_prefix
                ):
                    candidate = candidate[len(normalized_prefix) :]
                    candidates.add(candidate)
                    stripped_prefix = True
                    break
        mentions.append(frozenset(candidates))
    return tuple(mentions)


def _quoted_filename_replacement(match: re.Match[str]) -> str:
    value = unicodedata.normalize("NFKC", match.group(1)).strip()
    return "" if _SPREADSHEET_FILENAME_PATTERN.search(value) is not None else value


def _event_result_terms(question: str) -> tuple[str, ...]:
    quoted = tuple(
        value
        for match in _QUOTED_TERM_PATTERN.finditer(question)
        if (value := unicodedata.normalize("NFKC", match.group(1)).strip())
        and any(marker in value for marker in _EVENT_RESULT_TERM_MARKERS)
        and _SPREADSHEET_FILENAME_PATTERN.search(value) is None
        and not value.endswith(("文件", "工作簿", "考勤表", "数据表"))
        and not any(token in value for token in ("有没有", "是否", "有无", "或", "和", "与", "、"))
    )
    discovery_question = _QUOTED_TERM_PATTERN.sub(_quoted_discovery_text, question)
    discovered = tuple(term for term in _EVENT_RESULT_QUERY_TERMS if term in discovery_question)
    candidates = (*quoted, *discovered)
    ordered = tuple(
        sorted(
            candidates,
            key=lambda term: (
                question.find(term) if term in question else len(question),
                -len(term),
            ),
        )
    )
    return _deduplicate_terms(ordered)


def _quoted_discovery_text(match: re.Match[str]) -> str:
    value = unicodedata.normalize("NFKC", match.group(1)).strip()
    if _SPREADSHEET_FILENAME_PATTERN.search(value) is not None or value.endswith(
        ("文件", "工作簿", "考勤表", "数据表")
    ):
        return ""
    return value


def _deduplicate_terms(terms: tuple[str, ...]) -> tuple[str, ...]:
    selected: list[str] = []
    for term in terms:
        if (
            len(term) > _MAX_LABEL_CHARACTERS
            or term in selected
            or any(term in existing for existing in selected)
        ):
            continue
        selected = [existing for existing in selected if existing not in term]
        selected.append(term)
    return tuple(selected)


def _event_result_matches(value: str, term: str) -> bool:
    normalized_value = unicodedata.normalize("NFKC", value).casefold().strip()
    normalized_term = unicodedata.normalize("NFKC", term).casefold().strip()
    if not normalized_value or not normalized_term:
        return False
    if normalized_value == normalized_term or normalized_value.startswith(normalized_term):
        return True
    return any(
        segment.startswith(normalized_term)
        for segment in _EVENT_RESULT_SEGMENT_PATTERN.split(normalized_value)
        if segment
    )


async def _load_sources(
    session: AsyncSession, knowledge_base_id: UUID
) -> tuple[_EntrySource, ...] | None:
    statement = (
        select(KnowledgeEntry, File.id, OkfConversionJob.id)
        .outerjoin(
            File,
            (File.id == KnowledgeEntry.source_file_id)
            & (File.knowledge_base_id == KnowledgeEntry.knowledge_base_id),
        )
        .outerjoin(
            OkfConversionJob,
            (OkfConversionJob.output_entry_id == KnowledgeEntry.id)
            & (OkfConversionJob.file_id == KnowledgeEntry.source_file_id)
            & (OkfConversionJob.knowledge_base_id == KnowledgeEntry.knowledge_base_id)
            & (OkfConversionJob.status == OkfConversionStatus.SUCCEEDED),
        )
        .where(
            KnowledgeEntry.knowledge_base_id == knowledge_base_id,
            KnowledgeEntry.deleted_at.is_(None),
            KnowledgeEntry.publication_status == KnowledgeEntryPublicationStatus.PUBLISHED,
            KnowledgeEntry.custom_metadata["source_parser"].as_string().in_(_SOURCE_PARSERS),
        )
        .order_by(KnowledgeEntry.title, KnowledgeEntry.id)
        .limit(_MAX_ENTRIES + 1)
    )
    rows = tuple((await session.execute(statement)).all())
    if not rows or len(rows) > _MAX_ENTRIES:
        return None
    # Parser metadata and hashes live beside the parsed text and can therefore be
    # self-signed by a historical API write. Trust only entries linked back to the
    # immutable source file by the successful conversion job that produced them.
    if any(
        source_file_id is None or conversion_job_id is None
        for _, source_file_id, conversion_job_id in rows
    ):
        return None
    entries = tuple(entry for entry, _, _ in rows)
    updated_entry_audit = await session.scalar(
        select(AuditLog.id)
        .where(
            AuditLog.action == "knowledge_entry.updated",
            AuditLog.result == AuditResult.SUCCESS,
            AuditLog.resource_type == "knowledge_entry",
            AuditLog.resource_id.in_(tuple(str(entry.id) for entry in entries)),
        )
        .limit(1)
    )
    if updated_entry_audit is not None:
        return None
    if sum(len(entry.content) for entry in entries) > _MAX_TOTAL_CHARACTERS:
        return None
    sources: list[_EntrySource] = []
    for entry in entries:
        generator = entry.custom_metadata.get("generator")
        if (
            not isinstance(generator, dict)
            or generator.get("provider") != "local"
            or generator.get("model") != "local-deterministic-v1"
        ):
            return None
        raw_locations = entry.custom_metadata.get("source_locations")
        if not isinstance(raw_locations, list) or not all(
            isinstance(location, str) for location in raw_locations
        ):
            return None
        source_locations = tuple(raw_locations)
        if (
            not source_locations
            or len(source_locations) > _MAX_METADATA_LOCATIONS
            or len(set(source_locations)) != len(source_locations)
            or not all(_valid_source_location(location) for location in source_locations)
        ):
            return None
        source_location_count = entry.custom_metadata.get("source_location_count")
        locations_truncated = entry.custom_metadata.get("source_locations_truncated")
        source_text_length = entry.custom_metadata.get("source_text_length")
        source_text_sha256 = entry.custom_metadata.get("source_text_sha256")
        source_locations_sha256 = entry.custom_metadata.get("source_locations_sha256")
        integrity_values = (
            source_location_count,
            locations_truncated,
            source_text_length,
            source_text_sha256,
            source_locations_sha256,
        )
        integrity_metadata = all(value is not None for value in integrity_values)
        if any(value is not None for value in integrity_values) and not integrity_metadata:
            return None
        if integrity_metadata:
            if (
                not isinstance(source_location_count, int)
                or isinstance(source_location_count, bool)
                or source_location_count < len(source_locations)
                or not isinstance(locations_truncated, bool)
                or locations_truncated != (source_location_count > len(source_locations))
                or not isinstance(source_text_length, int)
                or isinstance(source_text_length, bool)
                or source_text_length <= 0
                or source_text_length > len(entry.content)
                or not isinstance(source_text_sha256, str)
                or _SHA256_PATTERN.fullmatch(source_text_sha256) is None
                or not isinstance(source_locations_sha256, str)
                or _SHA256_PATTERN.fullmatch(source_locations_sha256) is None
            ):
                return None
            source_text = entry.content[-source_text_length:]
            if sha256(source_text.encode("utf-8")).hexdigest() != source_text_sha256:
                return None
        else:
            if len(source_locations) >= _MAX_METADATA_LOCATIONS:
                return None
            legacy_source_text = _legacy_source_text(entry.content)
            if legacy_source_text is None:
                return None
            source_text = legacy_source_text
            source_location_count = None
            locations_truncated = False
            source_text_sha256 = sha256(source_text.encode("utf-8")).hexdigest()
            source_locations_sha256 = None
        sources.append(
            _EntrySource(
                id=entry.id,
                source_file_id=entry.source_file_id,
                title=entry.title,
                source_path=entry.source_path,
                format_version=entry.format_version,
                source_text=source_text,
                source_locations=source_locations,
                source_location_count=source_location_count,
                locations_truncated=locations_truncated,
                source_text_sha256=source_text_sha256,
                source_locations_sha256=source_locations_sha256,
                integrity_metadata=integrity_metadata,
            )
        )
    return tuple(sources)


def _select_sources(
    sources: tuple[_EntrySource, ...], question: str
) -> tuple[_EntrySource, ...] | None:
    normalized_question = unicodedata.normalize("NFKC", question).casefold()
    direct_matches: list[tuple[int, int, _EntrySource]] = []
    for source in sources:
        for filename in _source_spreadsheet_filenames(source):
            if not any(character.isspace() for character in filename):
                continue
            start = normalized_question.find(filename)
            while start >= 0:
                prefix_text = normalized_question[:start]
                has_boundary = start == 0 or normalized_question[start - 1] in (
                    " \t\r\n，。？！?：:；;、/\\\"'“”‘’《》【】()（）"
                )
                has_known_prefix = any(
                    prefix_text.endswith(unicodedata.normalize("NFKC", prefix).casefold())
                    for prefix in _SPREADSHEET_REFERENCE_PREFIXES
                )
                if has_boundary or has_known_prefix:
                    direct_matches.append((start, start + len(filename), source))
                start = normalized_question.find(filename, start + 1)
    if direct_matches:
        visible_matches = tuple(
            match
            for match in direct_matches
            if not any(
                other_start <= match[0]
                and match[1] <= other_end
                and (other_start, other_end) != match[:2]
                for other_start, other_end, _ in direct_matches
            )
        )
        directly_selected = {match[2].id: match[2] for match in visible_matches}
        if len(directly_selected) != 1:
            return None
        return (next(iter(directly_selected.values())),)

    explicit_mentions = _mentioned_spreadsheet_filename_candidates(question)
    if explicit_mentions:
        explicitly_selected: dict[UUID, _EntrySource] = {}
        for mention in explicit_mentions:
            matches = [
                source
                for source in sources
                if not _source_spreadsheet_filenames(source).isdisjoint(mention)
            ]
            if len(matches) != 1:
                return None
            explicitly_selected[matches[0].id] = matches[0]
        if len(explicitly_selected) != 1:
            return None
        return (next(iter(explicitly_selected.values())),)
    if len(sources) == 1:
        return sources
    fingerprints = {_source_fingerprint(source) for source in sources}
    return (sources[0],) if len(fingerprints) == 1 else None


def _source_spreadsheet_filenames(source: _EntrySource) -> frozenset[str]:
    title = unicodedata.normalize("NFKC", source.title).strip().casefold()
    if not title:
        return frozenset()
    if _SPREADSHEET_FILENAME_PATTERN.search(title) is not None:
        return frozenset((title,))
    return frozenset((f"{title}.xlsx", f"{title}.xls"))


def _strip_selected_source_filename_mentions(
    question: str,
    sources: tuple[_EntrySource, ...],
) -> str:
    stripped = unicodedata.normalize("NFKC", question)
    filenames = sorted(
        (filename for source in sources for filename in _source_spreadsheet_filenames(source)),
        key=len,
        reverse=True,
    )
    for filename in filenames:
        stripped = re.sub(re.escape(filename), "", stripped, flags=re.IGNORECASE)
    return stripped


def _source_fingerprint(source: _EntrySource) -> bytes:
    return bytes.fromhex(source.source_text_sha256)


def _reconstruct_sheets(sources: tuple[_EntrySource, ...]) -> tuple[_Sheet, ...]:
    reconstructed: list[_Sheet] = []
    total_rows = 0
    for source in sources:
        grouped: dict[tuple[str, int], dict[str, str]] = {}
        matches = tuple(_CELL_PATTERN.finditer(source.source_text))
        if source.source_text.count("[worksheet:") != len(matches):
            return ()
        seen_locations: set[str] = set()
        full_location_order: list[str] = []
        seen_sheets: set[str] = set()
        for index, match in enumerate(matches):
            marker_prefix = source.source_text[max(0, match.start() - 2) : match.start()]
            if match.start() > 0 and marker_prefix != "\n\n":
                return ()
            end = (
                matches[index + 1].start() if index + 1 < len(matches) else len(source.source_text)
            )
            value = source.source_text[match.end() : end].strip()
            if not value:
                continue
            sheet_name = match.group("sheet")
            row_number = int(match.group("row"))
            column = match.group("column").upper()
            location = f"worksheet:{sheet_name}!{column}{row_number}"
            if (
                location in seen_locations
                or row_number > _MAX_EXCEL_ROW
                or _column_number(column) > _MAX_EXCEL_COLUMN
                or len(value) > _MAX_CELL_CHARACTERS
            ):
                return ()
            seen_locations.add(location)
            if sheet_name not in seen_sheets:
                seen_sheets.add(sheet_name)
                full_location_order.append(f"worksheet:{sheet_name}")
            full_location_order.append(location)
            key = (sheet_name, row_number)
            cells = grouped.setdefault(key, {})
            if column in cells and cells[column] != value:
                return ()
            cells[column] = value
        trusted_locations = source.source_locations
        if tuple(full_location_order[: len(trusted_locations)]) != trusted_locations:
            return ()
        if source.integrity_metadata:
            if len(full_location_order) != source.source_location_count:
                return ()
            location_digest = sha256("\n".join(full_location_order).encode("utf-8")).hexdigest()
            if location_digest != source.source_locations_sha256:
                return ()
        elif not source.locations_truncated and tuple(full_location_order) != trusted_locations:
            return ()
        by_sheet: dict[str, list[_Row]] = {}
        for (sheet_name, row_number), cells in grouped.items():
            row = _Row(
                entry=source,
                sheet=sheet_name,
                number=row_number,
                cells=tuple(
                    _Cell(column=column, value=value)
                    for column, value in sorted(
                        cells.items(), key=lambda item: _column_number(item[0])
                    )
                ),
            )
            by_sheet.setdefault(sheet_name, []).append(row)
        for rows in by_sheet.values():
            ordered = tuple(sorted(rows, key=lambda item: item.number))
            inferred = _infer_sheet(ordered)
            if inferred is not None:
                reconstructed.append(inferred)
                total_rows += len(inferred.rows)
                if total_rows > _MAX_ROWS:
                    return ()
    return tuple(reconstructed)


def _all_source_sheets_reconstructed(
    sources: tuple[_EntrySource, ...],
    sheets: tuple[_Sheet, ...],
) -> bool:
    source_sheet_keys = {
        (source.id, match.group("sheet"))
        for source in sources
        for match in _CELL_PATTERN.finditer(source.source_text)
    }
    reconstructed_sheet_keys = {
        (sheet.rows[0].entry.id, sheet.rows[0].sheet) for sheet in sheets if sheet.rows
    }
    return bool(source_sheet_keys) and source_sheet_keys == reconstructed_sheet_keys


def _infer_sheet(rows: tuple[_Row, ...]) -> _Sheet | None:
    candidates: list[tuple[int, int, int, _Row, dict[str, str | None], frozenset[str]]] = []
    for row in rows[:50]:
        by_kind: dict[str, list[tuple[int, str]]] = {}
        for cell in row.cells:
            normalized = _normalize_header(cell.value)
            for kind, aliases in _HEADER_ALIASES.items():
                if normalized in aliases:
                    by_kind.setdefault(kind, []).append((aliases[normalized], cell.column))
        if not by_kind:
            continue
        resolved: dict[str, str | None] = {}
        row_ambiguous: set[str] = set()
        for kind, options in by_kind.items():
            best_priority = min(priority for priority, _ in options)
            best_columns = {column for priority, column in options if priority == best_priority}
            if len(best_columns) == 1:
                resolved[kind] = next(iter(best_columns))
            else:
                resolved[kind] = None
                row_ambiguous.add(kind)
        candidates.append(
            (
                len(resolved) - len(row_ambiguous),
                len(by_kind),
                -row.number,
                row,
                resolved,
                frozenset(row_ambiguous),
            )
        )
    if not candidates:
        return None
    attendance_header_count = sum(
        1
        for _, _, _, _, resolved, ambiguities in candidates
        if resolved.get("timestamp") is not None
        and "timestamp" not in ambiguities
        and resolved.get("device") is not None
        and "device" not in ambiguities
        and any(
            resolved.get(kind) is not None and kind not in ambiguities
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
    )
    _, _, _, header, columns, header_ambiguities = max(candidates, key=lambda item: item[:3])
    if len(columns) < 2:
        return None
    return _Sheet(
        rows=tuple(row for row in rows if row.number > header.number),
        columns=columns,
        ambiguous=header_ambiguities,
        multiple_attendance_headers=attendance_header_count > 1,
    )


def _should_use_generic_attendance_aggregate(
    plan: AttendanceAggregationPlan,
    question: str,
) -> bool:
    """Keep the mature unfiltered legacy answers while extending all new plans."""

    if plan.date_range is not None:
        return True
    semantic = _normalize_event_result_query_aliases(_strip_spreadsheet_filename_mentions(question))
    if _event_result_terms(semantic):
        return True
    if _QUOTED_TERM_PATTERN.search(semantic) is not None:
        return True
    if (
        plan.mode is AttendanceAggregateMode.DISTINCT
        and plan.dimension is AttendanceAggregateDimension.DEPARTMENT
    ):
        return False
    if re.search(r"[A-Za-z0-9一-鿿·_-]{1,30}(?:部|科|中心)", semantic):
        return True
    if re.search(r"[A-Za-z0-9一-鿿#_-]{1,30}(?:门|入口|出口)(?:设备|闸机)?", semantic):
        return True
    return not (
        plan.mode is AttendanceAggregateMode.GROUP_COUNT
        and plan.selection is AttendanceAggregateSelection.MAX
        and plan.dimension
        in (AttendanceAggregateDimension.EMPLOYEE, AttendanceAggregateDimension.DEVICE)
    )


def _answer_attendance_aggregate(
    sheets: tuple[_Sheet, ...],
    plan: AttendanceAggregationPlan,
    question: str,
) -> SpreadsheetAnswer | None:
    """Evaluate a verified attendance aggregate without retrieval or an LLM."""

    attendance_sheets = _attendance_sheets_for_aggregate(sheets)
    if attendance_sheets is None or not attendance_sheets:
        return None

    dimension = plan.dimension
    requires_employee = (
        dimension is AttendanceAggregateDimension.EMPLOYEE
        or plan.mode
        in (
            AttendanceAggregateMode.PER_CAPITA,
            AttendanceAggregateMode.DEPARTMENT_PROFILE,
        )
    )
    requires_department = (
        dimension is AttendanceAggregateDimension.DEPARTMENT
        or plan.mode
        in (
            AttendanceAggregateMode.PER_CAPITA,
            AttendanceAggregateMode.DEPARTMENT_PROFILE,
        )
    )
    event_terms = _event_result_terms(
        _normalize_event_result_query_aliases(_strip_spreadsheet_filename_mentions(question))
    )
    requires_event_result = dimension is AttendanceAggregateDimension.EVENT_RESULT or bool(
        event_terms
    )
    identifier_kind = next(
        (
            kind
            for kind in ("employee_id", "card_number")
            if all(
                sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
                for sheet in attendance_sheets
            )
        ),
        None,
    )
    has_common_employee_name = all(
        sheet.columns.get("employee_name") is not None and "employee_name" not in sheet.ambiguous
        for sheet in attendance_sheets
    )
    if requires_employee and (identifier_kind is None or not has_common_employee_name):
        return None
    if requires_department and any(
        sheet.columns.get("department") is None or "department" in sheet.ambiguous
        for sheet in attendance_sheets
    ):
        return None
    if requires_event_result and any(
        sheet.columns.get("event_result") is None or "event_result" in sheet.ambiguous
        for sheet in attendance_sheets
    ):
        return None

    records: list[_AttendanceAggregateRecord] = []
    records_by_sheet: list[tuple[_Sheet, tuple[_AttendanceAggregateRecord, ...]]] = []
    identifier_labels: dict[str, str] = {}
    employee_names: dict[str, str] = {}
    identifier_to_name: dict[str, str] = {}
    name_to_identifier: dict[str, str] = {}
    row_origins: dict[tuple[tuple[str, str], ...], tuple[UUID, str]] = {}

    for sheet in attendance_sheets:
        timestamp_column = sheet.columns.get("timestamp")
        device_column = sheet.columns.get("device")
        department_column = sheet.columns.get("department")
        event_type_column = sheet.columns.get("event_type")
        event_result_column = sheet.columns.get("event_result")
        name_column = sheet.columns.get("employee_name")
        identifier_column = sheet.columns.get(identifier_kind) if identifier_kind else None
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name", "department")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if timestamp_column is None or device_column is None or not identity_columns:
            return None
        sheet_records: list[_AttendanceAggregateRecord] = []
        for row in sheet.rows:
            if not row.entry.integrity_metadata:
                return None
            # Attendance worksheets must be proven disjoint before their rows
            # can be combined.  An exact row repeated in another worksheet is
            # evidence of an overlapping export/backup sheet; counting both
            # would silently inflate every aggregate.  Duplicates inside one
            # worksheet remain valid because two identical access events can
            # legitimately be emitted by the source system.
            row_fingerprint = tuple(
                (
                    cell.column,
                    re.sub(
                        r"\s+",
                        " ",
                        unicodedata.normalize("NFKC", cell.value).strip(),
                    ),
                )
                for cell in row.cells
            )
            row_origin = (row.entry.id, row.sheet)
            previous_origin = row_origins.setdefault(row_fingerprint, row_origin)
            if previous_origin != row_origin:
                return None
            raw_timestamp = row.value(timestamp_column)
            timestamp = _parse_datetime(raw_timestamp or "")
            normalized_device = _normalized_device_label(row.value(device_column) or "")
            if timestamp is None or normalized_device is None:
                return None
            if not any(
                _normalized_identity_label(row.value(column) or "") is not None
                for column in identity_columns
            ):
                return None

            employee_key: str | None = None
            employee_identifier: str | None = None
            employee_name: str | None = None
            if identifier_column is not None and name_column is not None:
                employee_identifier = _normalized_identity_label(row.value(identifier_column) or "")
                employee_name = _normalized_identity_label(row.value(name_column) or "")
                if employee_identifier is None or employee_name is None:
                    return None
                employee_key = re.sub(r"\s+", "", employee_identifier.casefold())
                name_key = re.sub(r"\s+", "", employee_name.casefold())
                if (
                    identifier_to_name.setdefault(employee_key, name_key) != name_key
                    or name_to_identifier.setdefault(name_key, employee_key) != employee_key
                ):
                    return None
                identifier_labels.setdefault(employee_key, employee_identifier)
                employee_names.setdefault(employee_key, employee_name)
            elif requires_employee:
                return None

            department_key: str | None = None
            department_label: str | None = None
            if department_column is not None and "department" not in sheet.ambiguous:
                normalized_department = _normalized_department_label(
                    row.value(department_column) or ""
                )
                if normalized_department is None:
                    if requires_department:
                        return None
                else:
                    department_key, department_label = normalized_department
            elif requires_department:
                return None

            event_result_key: str | None = None
            event_result_label: str | None = None
            if event_result_column is not None and "event_result" not in sheet.ambiguous:
                event_result_label = _normalized_identity_label(
                    row.value(event_result_column) or ""
                )
                if event_result_label is None:
                    if requires_event_result:
                        return None
                else:
                    event_result_key = event_result_label.casefold()
            elif requires_event_result:
                return None

            device_key, device_label = normalized_device
            event_type_key: str | None = None
            event_type_label: str | None = None
            if event_type_column is not None and "event_type" not in sheet.ambiguous:
                event_type_label = _normalized_identity_label(row.value(event_type_column) or "")
                if event_type_label is not None:
                    event_type_key = event_type_label.casefold()
            record = _AttendanceAggregateRecord(
                row=row,
                timestamp=timestamp,
                employee_key=employee_key,
                employee_identifier=employee_identifier,
                employee_name=employee_name,
                department_key=department_key,
                department_label=department_label,
                device_key=device_key,
                device_label=device_label,
                event_type_key=event_type_key,
                event_type_label=event_type_label,
                event_result_key=event_result_key,
                event_result_label=event_result_label,
            )
            records.append(record)
            sheet_records.append(record)
        records_by_sheet.append((sheet, tuple(sheet_records)))

    if not records:
        return None
    filters = _resolve_attendance_aggregate_filters(records, plan, question, event_terms)
    if filters is None:
        return None
    if filters.employee_keys and (identifier_kind is None or not has_common_employee_name):
        return None
    if filters.department_keys and any(record.department_key is None for record in records):
        return None
    if filters.event_type_keys and any(record.event_type_key is None for record in records):
        return None
    if filters.event_result_terms and any(record.event_result_label is None for record in records):
        return None

    matched_by_sheet: list[tuple[_Sheet, tuple[_AttendanceAggregateRecord, ...]]] = []
    matched_records: list[_AttendanceAggregateRecord] = []
    for sheet, sheet_record_group in records_by_sheet:
        matching = tuple(
            record
            for record in sheet_record_group
            if _attendance_record_matches(record, plan, filters)
        )
        matched_by_sheet.append((sheet, matching))
        matched_records.extend(matching)

    coverages = _attendance_aggregate_coverages(
        matched_by_sheet,
        dimension=dimension,
        filters=filters,
        identifier_kind=identifier_kind,
    )
    hits = _build_attendance_aggregate_hits(coverages)
    if hits is None or not hits:
        return None
    return _render_attendance_aggregate(
        plan,
        records,
        matched_records,
        filters,
        identifier_kind,
        identifier_labels,
        employee_names,
        hits,
    )


def _attendance_sheets_for_aggregate(
    sheets: tuple[_Sheet, ...],
) -> tuple[_Sheet, ...] | None:
    selected: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        identity_shape = any(
            kind in sheet.columns
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        signals = sum((timestamp_shape, device_shape, identity_shape))
        if not ((timestamp_shape or device_shape) and signals >= 2):
            continue
        if not (timestamp_shape and device_shape and identity_shape and sheet.rows):
            return None
        if any(
            sheet.columns.get(kind) is None or kind in sheet.ambiguous
            for kind in ("timestamp", "device")
        ):
            return None
        if not any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name", "department")
        ):
            return None
        if not _valid_coverage_sheet_name(sheet.rows[0].sheet):
            return None
        selected.append(sheet)
    return tuple(selected)


def _has_cross_sheet_duplicate_attendance_rows(sheets: tuple[_Sheet, ...]) -> bool:
    """Return whether attendance worksheets have an exact overlapping row."""

    attendance_sheets = _attendance_sheets_for_aggregate(sheets)
    if attendance_sheets is None:
        return False
    origins: dict[tuple[tuple[str, str], ...], tuple[UUID, str]] = {}
    for sheet in attendance_sheets:
        for row in sheet.rows:
            fingerprint = tuple(
                (
                    cell.column,
                    re.sub(
                        r"\s+",
                        " ",
                        unicodedata.normalize("NFKC", cell.value).strip(),
                    ),
                )
                for cell in row.cells
            )
            origin = (row.entry.id, row.sheet)
            previous_origin = origins.setdefault(fingerprint, origin)
            if previous_origin != origin:
                return True
    return False


def _resolve_attendance_aggregate_filters(
    records: list[_AttendanceAggregateRecord],
    plan: AttendanceAggregationPlan,
    question: str,
    event_terms: tuple[str, ...],
) -> _AttendanceAggregateFilters | None:
    semantic = unicodedata.normalize(
        "NFKC", _strip_spreadsheet_filename_mentions(question)
    ).casefold()
    employee_keys = {
        record.employee_key
        for record in records
        if record.employee_key is not None
        and any(
            label is not None
            and len(re.sub(r"\s+", "", label)) >= 2
            and label.casefold() in semantic
            for label in (record.employee_name, record.employee_identifier)
        )
    }
    department_keys = {
        record.department_key
        for record in records
        if record.department_key is not None
        and record.department_label is not None
        and record.department_label.casefold() in semantic
    }
    exact_device_keys = {
        record.device_key
        for record in records
        if len(re.sub(r"\s+", "", record.device_label)) >= 2
        and record.device_label.casefold() in semantic
    }
    if exact_device_keys:
        device_keys = exact_device_keys
    elif plan.device_contains is not None:
        device_keys = {
            record.device_key
            for record in records
            if plan.device_contains in re.sub(r"\s+", "", record.device_label.casefold())
        }
        if not device_keys:
            return None
    else:
        device_keys = set()
    event_type_keys = {
        record.event_type_key
        for record in records
        if record.event_type_key is not None
        and record.event_type_label is not None
        and record.event_type_label.casefold() in semantic
    }
    # Multiple values of the same field are deliberately rejected: natural
    # language conjunction/exclusion semantics are otherwise easy to misread.
    if (
        any(len(values) > 1 for values in (employee_keys, department_keys, event_type_keys))
        or (len(device_keys) > 1 and plan.device_contains is None)
    ):
        return None
    resolved_labels = {
        label.casefold()
        for record in records
        for label in (
            record.employee_name,
            record.employee_identifier,
            record.department_label,
            record.device_label,
            record.event_type_label,
        )
        if label is not None and label.casefold() in semantic
    }
    for match in _QUOTED_TERM_PATTERN.finditer(semantic):
        quoted = match.group(1).strip().casefold()
        if (
            quoted
            and _SPREADSHEET_FILENAME_PATTERN.search(quoted) is None
            and quoted not in resolved_labels
            and not _is_aggregate_presentation_quote(quoted)
            and not (
                plan.device_contains is not None
                and plan.device_contains in re.sub(r"\s+", "", quoted)
            )
            and not any(quoted == term.casefold() for term in event_terms)
        ):
            return None
    if _has_unresolved_attendance_filter(
        semantic,
        employee_keys=frozenset(key for key in employee_keys if key is not None),
        department_keys=frozenset(key for key in department_keys if key is not None),
        device_keys=frozenset(device_keys),
        event_type_keys=frozenset(key for key in event_type_keys if key is not None),
        event_result_terms=event_terms,
        resolved_labels=frozenset(resolved_labels),
        suppress_bare_employee=(
            plan.mode
            in (
                AttendanceAggregateMode.PER_CAPITA,
                AttendanceAggregateMode.DEPARTMENT_PROFILE,
            )
            or plan.dimension is AttendanceAggregateDimension.DATE
            or plan.selection is AttendanceAggregateSelection.COUNT_VALUES
            or plan.device_contains is not None
        ),
    ):
        return None
    return _AttendanceAggregateFilters(
        employee_keys=frozenset(key for key in employee_keys if key is not None),
        department_keys=frozenset(key for key in department_keys if key is not None),
        device_keys=frozenset(device_keys),
        event_type_keys=frozenset(key for key in event_type_keys if key is not None),
        event_result_terms=event_terms,
    )


def _is_aggregate_presentation_quote(value: str) -> bool:
    """Allow quoted metric wording while keeping unknown quoted filters fail-closed."""

    compact = re.sub(r"\s+", "", value)
    return compact in {
        "人均打卡次数",
        "人均考勤次数",
        "最忙",
        "记录总数最多",
        "第一条",
        "最早",
    }


def _has_unresolved_attendance_filter(
    question: str,
    *,
    employee_keys: frozenset[str],
    department_keys: frozenset[str],
    device_keys: frozenset[str],
    event_type_keys: frozenset[str],
    event_result_terms: tuple[str, ...],
    resolved_labels: frozenset[str],
    suppress_bare_employee: bool,
) -> bool:
    """Detect a syntactic exact scope that matched no trusted table value."""

    # Event type is a separate business field from the whitelisted event
    # result/status dimension.  Until it has its own typed plan, treating a
    # qualifier such as "普通消息事件类型" as a result filter would be wrong.
    if "事件类型" in question and not event_type_keys:
        return True

    if re.search(r"[A-Za-z0-9一-鿿·_-]{1,16}消息", question) and not event_type_keys:
        return True

    named_event_type = re.search(
        r"(?P<label>[A-Za-z0-9一-鿿·_-]{1,16}?)(?:事件|类型|类别)"
        r"(?=(?:有多少|有几|一共|总共|共计|多少|几条|打卡|记录|次数))",
        question,
    )
    if named_event_type is not None and not event_type_keys:
        event_label = named_event_type.group("label")
        if not any(term.casefold() in event_label for term in event_result_terms):
            return True

    # A status-looking qualifier that was not compiled by
    # ``_event_result_terms`` must never disappear into a global count.
    unknown_event_scope = re.search(
        r"(?:认证|验证)(?P<qualifier>[A-Za-z0-9一-鿿·_-]{1,16}?)"
        r"(?=(?:有多少|有几|一共|总共|共计|打卡|刷卡|通行|记录|结果|状态|次数))",
        question,
    )
    if not event_result_terms and unknown_event_scope is not None:
        qualifier = unknown_event_scope.group("qualifier")
        aggregate_language = ("多少", "几条", "总数", "数量", "一共", "总共", "共计", "全部")
        if not any(term in qualifier for term in aggregate_language):
            return True

    named_organization = re.search(
        r"[A-Za-z0-9一-鿿·_-]{1,30}(?:部(?!门)|科(?!室)|课|中心|车间)",
        question,
    )
    if named_organization is not None and not department_keys:
        return True
    named_device = re.search(
        r"[A-Za-z0-9一-鿿#_-]{1,30}(?<!部)门(?!禁)(?:设备|闸机)?",
        question,
    )
    if named_device is not None and not device_keys:
        return True
    global_scope_terms = (
        "考勤",
        "记录",
        "数据",
        "全体",
        "全部",
        "公司",
        "整个",
        "这份",
        "其中",
        "部门",
        "设备",
        "闸机",
        "打卡",
        "门禁",
        "刷卡",
        "通行",
        "全员",
        "人员",
        "员工",
        "职工",
        "本表",
        "该表",
        "本次",
        "大家",
        "所有人",
        "本文件",
        "表格",
        "整表",
        "整体",
        "所有员工",
        "全体员工",
        "分别",
        "每位",
        "每个",
        "各位",
        "哪位",
        "哪台",
        "哪个",
        "哪种",
        "哪些",
        "什么",
        "名单",
    )
    explicit_employee = re.search(
        r"(?:员工|人员)\s*[“\"'‘]?"
        r"(?P<label>[一-鿿·]{2,4}|[A-Za-z][A-Za-z0-9._-]{1,29}|"
        r"[A-Za-z0-9_-]*\d[A-Za-z0-9_-]{1,29})[”\"'’]?\s*"
        r"(?:(?:一共|总共|累计|共)(?:有)?|有多少|有几|的?"
        r"(?:打卡|考勤|门禁|通行)|打卡总数)",
        question,
    )
    if explicit_employee is not None and not employee_keys:
        candidate = explicit_employee.group("label")
        if not any(term in candidate for term in global_scope_terms):
            return True

    # Chinese questions commonly omit the word "员工" (for example,
    # "王五一共有多少条打卡记录").  Only a short leading person-like token
    # is recognized here, and global dataset nouns are excluded explicitly.
    if suppress_bare_employee:
        return False
    bare_employee = re.search(
        r"(?:^|帮我查|请帮我查|请查|请统计|查询|统计|查一下)\s*"
        r"[“\"'‘]?(?P<label>[一-鿿·]{2,6}?)[”\"'’]?\s*"
        r"(?:(?:一共|总共|累计|共有|共计|共)(?:有)?|"
        r"(?:在[^，。？！?]{1,20})?的?(?:打卡|考勤|门禁|通行|刷卡)"
        r"(?:记录)?(?:(?:一共|总共|累计|共有|共计|共)(?:有)?)?"
        r"(?:多少|几|总数|次数)?|(?:有)?(?:多少|几)(?:条|次|个)?"
        r"(?:打卡|考勤|门禁|通行))",
        question,
    )
    if bare_employee is None or employee_keys or event_type_keys:
        return False
    candidate = bare_employee.group("label")
    candidate_key = candidate.casefold()
    if any(
        candidate_key == label
        or candidate_key in label
        or label in candidate_key
        for label in resolved_labels
    ):
        return False
    return not any(term in candidate for term in global_scope_terms)


def _attendance_record_matches(
    record: _AttendanceAggregateRecord,
    plan: AttendanceAggregationPlan,
    filters: _AttendanceAggregateFilters,
) -> bool:
    date_range = plan.date_range
    if date_range is not None and not (
        date_range.start <= record.timestamp.date() <= date_range.end
    ):
        return False
    if filters.employee_keys and record.employee_key not in filters.employee_keys:
        return False
    if filters.department_keys and record.department_key not in filters.department_keys:
        return False
    if filters.device_keys and record.device_key not in filters.device_keys:
        return False
    if filters.event_type_keys and record.event_type_key not in filters.event_type_keys:
        return False
    return not filters.event_result_terms or any(
        _event_result_matches(record.event_result_label or "", term)
        for term in filters.event_result_terms
    )


def _attendance_aggregate_coverages(
    records_by_sheet: list[tuple[_Sheet, tuple[_AttendanceAggregateRecord, ...]]],
    *,
    dimension: AttendanceAggregateDimension | None,
    filters: _AttendanceAggregateFilters,
    identifier_kind: str | None,
) -> list[_AttendanceAggregateCoverage]:
    coverages: list[_AttendanceAggregateCoverage] = []
    for sheet, matching in records_by_sheet:
        columns = {
            sheet.columns["timestamp"],
            sheet.columns["device"],
        }
        for kind in (identifier_kind, "employee_name"):
            if kind and (column := sheet.columns.get(kind)) is not None:
                columns.add(column)
        if (dimension is AttendanceAggregateDimension.DEPARTMENT or filters.department_keys) and (
            column := sheet.columns.get("department")
        ) is not None:
            columns.add(column)
        if (
            dimension is AttendanceAggregateDimension.EVENT_RESULT or filters.event_result_terms
        ) and (column := sheet.columns.get("event_result")) is not None:
            columns.add(column)
        if filters.event_type_keys and (column := sheet.columns.get("event_type")) is not None:
            columns.add(column)
        if filters.employee_keys:
            for kind in (identifier_kind, "employee_name"):
                if kind and (column := sheet.columns.get(kind)) is not None:
                    columns.add(column)
        coverages.append(
            _AttendanceAggregateCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                columns=tuple(sorted((column for column in columns if column), key=_column_number)),
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                matched_rows=len(matching),
            )
        )
    return coverages


def _build_attendance_aggregate_hits(
    coverages: list[_AttendanceAggregateCoverage],
) -> tuple[KnowledgeSearchHit, ...] | None:
    grouped: dict[UUID, list[_AttendanceAggregateCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchor_groups: list[tuple[str, ...]] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchors = tuple(
                _column_range(
                    coverage.sheet,
                    column,
                    coverage.first_row,
                    coverage.last_row,
                )
                for column in coverage.columns
            )
            anchor_groups.append(anchors)
            summaries.append(
                f"确定性全量聚合 [{', '.join(anchors)}]：完整扫描 "
                f"{coverage.scanned_rows} 条考勤记录；筛选后 {coverage.matched_rows} 条。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        anchor = _combined_grouped_coverage_anchor(anchor_groups)
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(entry.source_path, anchor),
                format_version=(
                    _citation_safe_text(entry.format_version) if entry.format_version else None
                ),
            )
        )
    return tuple(hits)


def _render_attendance_aggregate(
    plan: AttendanceAggregationPlan,
    scanned_records: list[_AttendanceAggregateRecord],
    matched_records: list[_AttendanceAggregateRecord],
    filters: _AttendanceAggregateFilters,
    identifier_kind: str | None,
    identifier_labels: dict[str, str],
    employee_names: dict[str, str],
    hits: tuple[KnowledgeSearchHit, ...],
) -> SpreadsheetAnswer | None:
    title_values = {record.row.entry.title for record in scanned_records}
    title = next(iter(title_values)) if len(title_values) == 1 else "选定考勤工作簿"
    safe_title = _citation_safe_text(title)
    citation = _citation_marker(hits)
    scanned_count = len(scanned_records)
    matched_count = len(matched_records)
    scope = _attendance_filter_scope(scanned_records, plan, filters)

    if plan.mode is AttendanceAggregateMode.TOTAL:
        if scope:
            answer = (
                f"在《{safe_title}》中已完整扫描 {scanned_count} 条有效考勤记录，"
                f"{scope}共有 {matched_count} 条打卡记录。{citation}"
            )
        else:
            answer = (
                f"在《{safe_title}》中已完整扫描 {scanned_count} 条有效考勤记录，"
                f"共有 {matched_count} 条打卡记录。{citation}"
            )
        return SpreadsheetAnswer(
            answer=answer,
            table=SpreadsheetTable(
                title="考勤记录总数",
                columns=("统计范围", "记录数"),
                rows=(
                    (
                        (scope or "全部考勤记录").replace("“", "").replace("”", ""),
                        f"{matched_count} 条",
                    ),
                ),
                citation_numbers=tuple(range(1, len(hits) + 1)),
            ),
            hits=hits,
        )

    dimension = plan.dimension
    if dimension is None:
        return None

    if plan.mode is AttendanceAggregateMode.DEPARTMENT_PROFILE:
        if len(filters.department_keys) != 1 or identifier_kind is None:
            return None
        employee_counts: dict[str, int] = {}
        for record in matched_records:
            if record.employee_key is None or record.employee_name is None:
                return None
            employee_counts[record.employee_key] = employee_counts.get(record.employee_key, 0) + 1
        profile_department_labels = {
            record.department_label
            for record in matched_records
            if record.department_label is not None
        }
        if len(profile_department_labels) != 1 or len(employee_counts) > _MAX_TABLE_ROWS:
            return None
        department_label = _citation_safe_text(next(iter(profile_department_labels)))
        ordered_employees = tuple(
            sorted(employee_counts, key=lambda key: (employee_names[key].casefold(), key))
        )
        safe_names = tuple(
            _citation_safe_text(employee_names[key]) for key in ordered_employees
        )
        return SpreadsheetAnswer(
            answer=(
                f"“{department_label}”共有 {len(ordered_employees)} 位员工："
                f"{'、'.join(safe_names)}；全表合计打卡 {matched_count} 次。{citation}"
            ),
            table=SpreadsheetTable(
                title=f"{department_label}员工与打卡统计",
                columns=(
                    "人员工号" if identifier_kind == "employee_id" else "卡号",
                    "员工姓名",
                    "打卡次数",
                ),
                rows=tuple(
                    (
                        _citation_safe_text(identifier_labels[key]),
                        _citation_safe_text(employee_names[key]),
                        f"{employee_counts[key]} 次",
                    )
                    for key in ordered_employees
                ),
                citation_numbers=tuple(range(1, len(hits) + 1)),
            ),
            hits=hits,
        )

    if plan.mode is AttendanceAggregateMode.PER_CAPITA:
        if identifier_kind is None:
            return None
        department_totals: dict[str, int] = {}
        department_people: dict[str, set[str]] = {}
        department_label_by_key: dict[str, str] = {}
        for record in matched_records:
            if (
                record.department_key is None
                or record.department_label is None
                or record.employee_key is None
            ):
                return None
            key = record.department_key
            department_totals[key] = department_totals.get(key, 0) + 1
            department_people.setdefault(key, set()).add(record.employee_key)
            department_label_by_key.setdefault(key, record.department_label)
        if not department_totals:
            return None
        averages = {
            key: Fraction(department_totals[key], len(department_people[key]))
            for key in department_totals
            if department_people[key]
        }
        if not averages:
            return None
        average_boundary = (
            max(averages.values())
            if plan.selection is AttendanceAggregateSelection.MAX
            else min(averages.values())
        )
        selected_departments = tuple(
            sorted(
                (key for key, value in averages.items() if value == average_boundary),
                key=lambda key: (department_label_by_key[key].casefold(), key),
            )
        )
        if len(selected_departments) > _MAX_TABLE_ROWS:
            return None
        rows = tuple(
            (
                _citation_safe_text(department_label_by_key[key]),
                str(len(department_people[key])),
                str(department_totals[key]),
                f"{float(averages[key]):.1f}",
            )
            for key in selected_departments
        )
        direction = "最高" if plan.selection is AttendanceAggregateSelection.MAX else "最低"
        per_capita_summaries = "；".join(
            f"“{row[0]}”共 {row[1]} 人、{row[2]} 次打卡，人均 {row[3]} 次"
            for row in rows
        )
        return SpreadsheetAnswer(
            answer=(
                f"人均打卡次数{direction}的部门统计如下："
                f"{per_capita_summaries}。{citation}"
            ),
            table=SpreadsheetTable(
                title="部门人均打卡统计",
                columns=("部门", "员工人数", "总打卡次数", "人均打卡次数"),
                rows=rows,
                citation_numbers=tuple(range(1, len(hits) + 1)),
            ),
            hits=hits,
        )

    values: dict[str, str] = {}
    counts: dict[str, int] = {}
    for record in matched_records:
        value = _attendance_dimension_value(record, dimension)
        if value is None:
            return None
        key, label = value
        values.setdefault(key, label)
        counts[key] = counts.get(key, 0) + 1

    dimension_name = _attendance_dimension_name(dimension)
    if plan.mode is AttendanceAggregateMode.DISTINCT:
        if len(values) > _MAX_TABLE_ROWS:
            return None
        if not values:
            return SpreadsheetAnswer(
                answer=(
                    f"在《{safe_title}》中已完整扫描 {scanned_count} 条有效考勤记录，"
                    f"筛选后无符合条件记录，共包含 0 个不同{dimension_name}。{citation}"
                ),
                table=None,
                hits=hits,
            )
        keys = tuple(values)
        labels = tuple(_citation_safe_text(values[key]) for key in keys)
        answer = (
            f"在《{safe_title}》中已完整扫描 {scanned_count} 条有效考勤记录，"
            f"共包含 {len(keys)} 个不同{dimension_name}：{'、'.join(labels)}。{citation}"
        )
        distinct_rows: tuple[tuple[str, ...], ...]
        distinct_columns: tuple[str, ...]
        if dimension is AttendanceAggregateDimension.EMPLOYEE:
            identifier_label = "人员工号" if identifier_kind == "employee_id" else "卡号"
            distinct_rows = tuple(
                (
                    _citation_safe_text(identifier_labels[key]),
                    _citation_safe_text(employee_names[key]),
                )
                for key in keys
            )
            distinct_columns = (identifier_label, "员工姓名")
        else:
            distinct_rows = tuple((label,) for label in labels)
            distinct_columns = (f"{dimension_name}名称",)
        return SpreadsheetAnswer(
            answer=answer,
            table=SpreadsheetTable(
                title=f"考勤{dimension_name}去重统计",
                columns=distinct_columns,
                rows=distinct_rows,
                citation_numbers=tuple(range(1, len(hits) + 1)),
            ),
            hits=hits,
        )

    if not counts:
        return SpreadsheetAnswer(
            answer=(
                f"在《{safe_title}》中已完整扫描 {scanned_count} 条有效考勤记录，"
                f"筛选后无符合条件记录。{citation}"
            ),
            table=None,
            hits=hits,
        )
    ranked = tuple(
        sorted(
            counts,
            key=lambda key: (-counts[key], values[key].casefold(), values[key], key),
        )
    )
    selected: tuple[str, ...]
    if plan.selection is AttendanceAggregateSelection.ALL:
        selected = ranked
    elif plan.selection is AttendanceAggregateSelection.MAX:
        highest = counts[ranked[0]]
        selected = tuple(key for key in ranked if counts[key] == highest)
    elif plan.selection is AttendanceAggregateSelection.MIN:
        lowest = min(counts.values())
        selected = tuple(key for key in ranked if counts[key] == lowest)
    elif plan.selection is AttendanceAggregateSelection.COUNT_VALUES:
        selected = tuple(key for key in ranked if counts[key] in plan.count_values)
    else:
        top_n = plan.top_n
        if top_n is None:
            return None
        count_boundary = counts[ranked[min(top_n, len(ranked)) - 1]]
        selected = tuple(key for key in ranked if counts[key] >= count_boundary)
    if len(selected) > _MAX_TABLE_ROWS:
        return None

    safe_labels = tuple(_citation_safe_text(values[key]) for key in selected)
    if (
        plan.device_contains is not None
        and dimension is AttendanceAggregateDimension.EMPLOYEE
        and plan.selection is AttendanceAggregateSelection.ALL
    ):
        if not selected or len(matched_records) > _MAX_TABLE_ROWS:
            return None
        device_rows = tuple(
            (
                _citation_safe_text(record.employee_identifier or "—"),
                _citation_safe_text(record.employee_name or "—"),
                record.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                _citation_safe_text(record.device_label),
            )
            for record in sorted(
                matched_records,
                key=lambda record: (record.timestamp, _row_sort_key(record.row)),
            )
        )
        return SpreadsheetAnswer(
            answer=(
                f"有，共 {len(selected)} 位员工通过包含“{plan.device_contains.upper()}”"
                f"的闸机打卡：{'、'.join(safe_labels)}；共 {matched_count} 条记录。{citation}"
            ),
            table=SpreadsheetTable(
                title=f"{plan.device_contains.upper()}闸机打卡明细",
                columns=(
                    "人员工号" if identifier_kind == "employee_id" else "卡号",
                    "员工姓名",
                    "时间",
                    "设备",
                ),
                rows=device_rows,
                citation_numbers=tuple(range(1, len(hits) + 1)),
            ),
            hits=hits,
        )

    if plan.selection is AttendanceAggregateSelection.MAX:
        if dimension is AttendanceAggregateDimension.EMPLOYEE:
            if len(selected) == 1:
                answer = (
                    f"在《{safe_title}》中已完整扫描 {scanned_count} 条打卡记录，"
                    f"打卡总次数最多的员工是“{safe_labels[0]}”，"
                    f"共打卡 {counts[selected[0]]} 次。{citation}"
                )
            else:
                answer = (
                    f"打卡总次数最多的员工有 {len(selected)} 位，并列第一："
                    f"{'、'.join(f'“{label}”' for label in safe_labels)}，"
                    f"各打卡 {counts[selected[0]]} 次。{citation}"
                )
        elif dimension is AttendanceAggregateDimension.DEVICE:
            if len(selected) == 1:
                answer = (
                    f"在《{safe_title}》中已完整扫描 {scanned_count} 条打卡记录，"
                    f"使用最频繁的设备是“{safe_labels[0]}”，"
                    f"共记录 {counts[selected[0]]} 次。{citation}"
                )
            else:
                answer = (
                    f"使用最频繁的设备有 {len(selected)} 个，并列第一："
                    f"{'、'.join(f'“{label}”' for label in safe_labels)}，"
                    f"各记录 {counts[selected[0]]} 次。{citation}"
                )
        elif dimension is AttendanceAggregateDimension.DATE:
            date_subject = (
                f"日期是{safe_labels[0]}"
                if len(safe_labels) == 1
                else f"日期有 {'、'.join(safe_labels)}，并列第一"
            )
            answer = f"考勤打卡最忙的{date_subject}，共记录 {counts[selected[0]]} 次。{citation}"
        else:
            answer = (
                f"{dimension_name}打卡次数最多的是"
                f"{'、'.join(f'“{label}”' for label in safe_labels)}，"
                f"共 {counts[selected[0]]} 次。{citation}"
            )
    elif plan.selection is AttendanceAggregateSelection.MIN:
        answer = (
            f"{dimension_name}打卡次数最少的是"
            f"{'、'.join(f'“{label}”' for label in safe_labels)}，"
            f"共 {counts[selected[0]]} 次。{citation}"
        )
    elif plan.selection is AttendanceAggregateSelection.TOP_N:
        answer = (
            f"{dimension_name}打卡次数前 {plan.top_n} 名如下；"
            f"若第 {plan.top_n} 名并列，已完整保留边界并列项。{citation}"
        )
    elif plan.selection is AttendanceAggregateSelection.COUNT_VALUES:
        if not selected:
            answer = f"没有员工的打卡次数属于 {list(plan.count_values)}。{citation}"
        else:
            grouped_by_count = {
                value: tuple(
                    _citation_safe_text(values[key])
                    for key in selected
                    if counts[key] == value
                )
                for value in plan.count_values
            }
            descriptions = tuple(
                f"打卡 {value} 次的员工有 {len(labels)} 人：{'、'.join(labels)}"
                for value, labels in grouped_by_count.items()
                if labels
            )
            answer = f"{'；'.join(descriptions)}。{citation}"
    else:
        answer = (
            f"在《{safe_title}》中已按{dimension_name}完成全量汇总，"
            f"共 {len(selected)} 个分组。{citation}"
        )

    identifier_label = "人员工号" if identifier_kind == "employee_id" else "卡号"
    grouped_columns: tuple[str, ...]
    grouped_rows: tuple[tuple[str, ...], ...]
    if dimension is AttendanceAggregateDimension.EMPLOYEE:
        grouped_columns = (identifier_label, "员工姓名", "打卡次数")
        grouped_rows = tuple(
            (
                _citation_safe_text(identifier_labels[key]),
                _citation_safe_text(employee_names[key]),
                f"{counts[key]} 次",
            )
            for key in selected
        )
    else:
        grouped_columns = (f"{dimension_name}名称", "打卡次数")
        grouped_rows = tuple(
            (_citation_safe_text(values[key]), f"{counts[key]} 次") for key in selected
        )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title=f"{dimension_name}打卡频次",
            columns=grouped_columns,
            rows=grouped_rows,
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _attendance_dimension_value(
    record: _AttendanceAggregateRecord,
    dimension: AttendanceAggregateDimension,
) -> tuple[str, str] | None:
    if dimension is AttendanceAggregateDimension.EMPLOYEE:
        if record.employee_key is None or record.employee_name is None:
            return None
        return record.employee_key, record.employee_name
    if dimension is AttendanceAggregateDimension.DEPARTMENT:
        if record.department_key is None or record.department_label is None:
            return None
        return record.department_key, record.department_label
    if dimension is AttendanceAggregateDimension.DEVICE:
        return record.device_key, record.device_label
    if dimension is AttendanceAggregateDimension.DATE:
        value = record.timestamp.date().isoformat()
        return value, value
    if record.event_result_key is None or record.event_result_label is None:
        return None
    return record.event_result_key, record.event_result_label


def _attendance_dimension_name(dimension: AttendanceAggregateDimension) -> str:
    return {
        AttendanceAggregateDimension.EMPLOYEE: "员工",
        AttendanceAggregateDimension.DEPARTMENT: "部门",
        AttendanceAggregateDimension.DEVICE: "设备",
        AttendanceAggregateDimension.EVENT_RESULT: "事件结果",
        AttendanceAggregateDimension.DATE: "日期",
    }[dimension]


def _attendance_filter_scope(
    records: list[_AttendanceAggregateRecord],
    plan: AttendanceAggregationPlan,
    filters: _AttendanceAggregateFilters,
) -> str:
    parts: list[str] = []
    if plan.date_range is not None:
        if plan.date_range.start == plan.date_range.end:
            parts.append(_format_date(plan.date_range.start))
        else:
            parts.append(
                f"{_format_date(plan.date_range.start)}至{_format_date(plan.date_range.end)}"
            )
    if filters.employee_keys:
        labels = {
            record.employee_name
            for record in records
            if record.employee_key in filters.employee_keys and record.employee_name is not None
        }
        parts.extend(f"员工“{_citation_safe_text(label)}”" for label in sorted(labels))
    if filters.department_keys:
        labels = {
            record.department_label
            for record in records
            if record.department_key in filters.department_keys
            and record.department_label is not None
        }
        parts.extend(f"“{_citation_safe_text(label)}”" for label in sorted(labels))
    if filters.device_keys:
        labels = {
            record.device_label for record in records if record.device_key in filters.device_keys
        }
        parts.extend(f"设备“{_citation_safe_text(label)}”" for label in sorted(labels))
    if filters.event_type_keys:
        labels = {
            record.event_type_label
            for record in records
            if record.event_type_key in filters.event_type_keys
            and record.event_type_label is not None
        }
        parts.extend(f"事件类型“{_citation_safe_text(label)}”" for label in sorted(labels))
    parts.extend(f"事件结果“{_citation_safe_text(term)}”" for term in filters.event_result_terms)
    return "、".join(parts)


def _answer_department_record_count(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        department_shape = "department" in sheet.columns
        identity_shape = any(
            kind in sheet.columns for kind in ("employee_id", "card_number", "employee_name")
        )
        attendance_shape_signals = sum(
            (timestamp_shape, device_shape, department_shape, identity_shape)
        )
        partial_attendance_shape = (
            timestamp_shape or device_shape
        ) and attendance_shape_signals >= 2
        if not partial_attendance_shape:
            continue
        if not (timestamp_shape and device_shape and department_shape and identity_shape):
            return None
        if not sheet.rows or not _valid_coverage_sheet_name(sheet.rows[0].sheet):
            return None
        department_column = sheet.columns.get("department")
        timestamp_column = sheet.columns.get("timestamp")
        device_column = sheet.columns.get("device")
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if (
            department_column is None
            or timestamp_column is None
            or device_column is None
            or not identity_columns
            or "department" in sheet.ambiguous
            or "timestamp" in sheet.ambiguous
            or "device" in sheet.ambiguous
        ):
            return None
        attendance_sheets.append(sheet)
    if not attendance_sheets:
        return None

    display_labels: dict[str, str] = {}
    total_counts: dict[str, int] = {}
    sheet_counts: list[tuple[_Sheet, str, str, dict[str, int]]] = []
    total_scanned = 0
    for sheet in attendance_sheets:
        department_column = sheet.columns.get("department")
        timestamp_column = sheet.columns.get("timestamp")
        device_column = sheet.columns.get("device")
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if (
            department_column is None
            or timestamp_column is None
            or device_column is None
            or not identity_columns
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None

        counts: dict[str, int] = {}
        for row in sheet.rows:
            raw_department = row.value(department_column)
            raw_timestamp = row.value(timestamp_column)
            raw_device = row.value(device_column)
            if (
                raw_department is None
                or raw_timestamp is None
                or _parse_datetime(raw_timestamp) is None
                or raw_device is None
                or _normalized_device_label(raw_device) is None
                or not any(
                    _normalized_identity_label(row.value(column) or "") is not None
                    for column in identity_columns
                )
            ):
                return None
            normalized_department = _normalized_department_label(raw_department)
            if normalized_department is None:
                return None
            department_key, display_label = normalized_department
            display_labels.setdefault(department_key, display_label)
            counts[department_key] = counts.get(department_key, 0) + 1
            total_counts[department_key] = total_counts.get(department_key, 0) + 1

        sheet_counts.append((sheet, department_column, timestamp_column, counts))
        total_scanned += len(sheet.rows)

    normalized_question = unicodedata.normalize("NFKC", question).casefold()
    target_keys = tuple(key for key in display_labels if key in normalized_question)
    if not target_keys:
        return None
    longest_length = max(len(key) for key in target_keys)
    longest_keys = tuple(key for key in target_keys if len(key) == longest_length)
    if len(longest_keys) != 1:
        return None
    target_key = longest_keys[0]
    target_display = display_labels[target_key]
    if _has_unsupported_department_record_count_scope(question, target_display):
        return None

    coverages = [
        _DepartmentRecordCountCoverage(
            entry=sheet.rows[0].entry,
            sheet=sheet.rows[0].sheet,
            department_column=department_column,
            timestamp_column=timestamp_column,
            first_row=sheet.rows[0].number,
            last_row=sheet.rows[-1].number,
            scanned_rows=len(sheet.rows),
            matched_rows=counts.get(target_key, 0),
        )
        for sheet, department_column, timestamp_column, counts in sheet_counts
    ]
    matched_count = total_counts.get(target_key, 0)
    hits = _build_department_record_count_hits(coverages, target_display)
    if hits is None or not hits or total_scanned <= 0:
        return None

    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    safe_title = _citation_safe_text(title)
    safe_department = _citation_safe_text(target_display)
    return SpreadsheetAnswer(
        answer=(
            f"在《{safe_title}》的完整考勤时间范围内，“{safe_department}”共有 "
            f"{matched_count} 条打卡记录（已完整扫描 {total_scanned} 条记录）。"
            f"{_citation_marker(hits)}"
        ),
        table=SpreadsheetTable(
            title="部门打卡记录统计",
            columns=("部门名称", "打卡记录数"),
            rows=((safe_department, f"{matched_count} 条"),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_department_summary(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    if _has_unsupported_department_summary_scope(question):
        return None

    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        identity_shape = any(
            kind in sheet.columns for kind in ("employee_id", "card_number", "employee_name")
        )
        if not (timestamp_shape and device_shape and identity_shape):
            continue
        if not sheet.rows:
            continue
        if not _valid_coverage_sheet_name(sheet.rows[0].sheet):
            return None
        timestamp_signal = (
            sheet.columns.get("timestamp") is not None and "timestamp" not in sheet.ambiguous
        )
        device_signal = sheet.columns.get("device") is not None and "device" not in sheet.ambiguous
        identity_signal = any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name")
        )
        department_column = sheet.columns.get("department")
        if (
            not timestamp_signal
            or not device_signal
            or not identity_signal
            or "department" not in sheet.columns
            or department_column is None
            or "department" in sheet.ambiguous
        ):
            return None
        attendance_sheets.append(sheet)
    if not attendance_sheets:
        return None

    display_labels: dict[str, str] = {}
    coverages: list[_DepartmentSummaryCoverage] = []
    total_scanned = 0
    for sheet in attendance_sheets:
        department_column = sheet.columns.get("department")
        timestamp_column = sheet.columns.get("timestamp")
        device_column = sheet.columns.get("device")
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if (
            department_column is None
            or timestamp_column is None
            or device_column is None
            or not identity_columns
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None

        sheet_department_keys: dict[str, None] = {}
        for row in sheet.rows:
            raw_timestamp = row.value(timestamp_column)
            raw_device = row.value(device_column)
            raw_department = row.value(department_column)
            if (
                raw_timestamp is None
                or _parse_datetime(raw_timestamp) is None
                or raw_device is None
                or _normalized_device_label(raw_device) is None
                or not any(
                    _normalized_identity_label(row.value(column) or "") is not None
                    for column in identity_columns
                )
                or raw_department is None
            ):
                return None
            normalized_department = _normalized_department_label(raw_department)
            if normalized_department is None:
                return None
            department_key, display_label = normalized_department
            display_labels.setdefault(department_key, display_label)
            sheet_department_keys.setdefault(department_key, None)
            if len(display_labels) > _MAX_TABLE_ROWS:
                return None

        coverages.append(
            _DepartmentSummaryCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                column=department_column,
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                departments=tuple(display_labels[key] for key in sheet_department_keys),
            )
        )
        total_scanned += len(sheet.rows)

    if not display_labels or total_scanned <= 0:
        return None
    hits = _build_department_summary_hits(coverages)
    if hits is None or not hits:
        return None

    departments = tuple(display_labels.values())
    safe_departments = "、".join(_citation_safe_text(label) for label in departments)
    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    answer = (
        f"在《{_citation_safe_text(title)}》中已完整扫描 {total_scanned} 条考勤记录，"
        f"共包含 {len(departments)} 个不同部门：{safe_departments}。{_citation_marker(hits)}"
    )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="考勤部门统计",
            columns=("部门名称",),
            rows=tuple((department,) for department in departments),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _normalized_department_label(value: str) -> tuple[str, str] | None:
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        return None
    display_label = re.sub(r"\s+", " ", normalized).strip()
    department_key = display_label.casefold()
    compact_key = re.sub(r"\s+", "", department_key)
    if (
        not display_label
        or len(display_label) > _MAX_LABEL_CHARACTERS
        or compact_key in _MISSING_DEPARTMENT_LABELS
        or not any(character.isalnum() for character in display_label)
    ):
        return None
    return department_key, display_label


def _valid_coverage_sheet_name(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    return bool(
        normalized
        and len(normalized) <= 31
        and not any(
            unicodedata.category(character).startswith("C") or character in ",#![]\r\n"
            for character in normalized
        )
    )


def _normalized_identity_label(value: str) -> str | None:
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        return None
    display_label = re.sub(r"\s+", " ", normalized).strip()
    compact_key = re.sub(r"\s+", "", display_label.casefold())
    if (
        not display_label
        or len(display_label) > _MAX_LABEL_CHARACTERS
        or compact_key in _MISSING_SPREADSHEET_VALUE_LABELS
        or not any(character.isalnum() for character in display_label)
    ):
        return None
    return display_label


def _answer_employee_frequency(
    sheets: tuple[_Sheet, ...],
    question: str,
) -> SpreadsheetAnswer | None:
    if _has_unsupported_employee_frequency_scope(question):
        return None

    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        name_shape = "employee_name" in sheet.columns
        stable_identity_shape = any(
            kind in sheet.columns for kind in ("employee_id", "card_number")
        )
        attendance_shape_signals = sum(
            (timestamp_shape, device_shape, name_shape, stable_identity_shape)
        )
        partial_attendance_shape = (
            timestamp_shape or device_shape
        ) and attendance_shape_signals >= 2
        if not partial_attendance_shape:
            continue
        if not (
            timestamp_shape and device_shape and name_shape and stable_identity_shape and sheet.rows
        ):
            return None
        if any(
            sheet.columns.get(kind) is None or kind in sheet.ambiguous
            for kind in ("timestamp", "device", "employee_name")
        ):
            return None
        attendance_sheets.append(sheet)
    if not attendance_sheets:
        return None

    identifier_kind = next(
        (
            kind
            for kind in ("employee_id", "card_number")
            if all(
                sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
                for sheet in attendance_sheets
            )
        ),
        None,
    )
    if identifier_kind is None:
        return None

    total_counts: dict[str, int] = {}
    identifier_labels: dict[str, str] = {}
    employee_names: dict[str, str] = {}
    identifier_to_name: dict[str, str] = {}
    name_to_identifier: dict[str, str] = {}
    sheet_counts: list[tuple[_Sheet, str, str, str, dict[str, int]]] = []
    total_scanned = 0

    for sheet in attendance_sheets:
        identifier_column = sheet.columns.get(identifier_kind)
        name_column = sheet.columns.get("employee_name")
        timestamp_column = sheet.columns.get("timestamp")
        device_column = sheet.columns.get("device")
        if (
            identifier_column is None
            or name_column is None
            or timestamp_column is None
            or device_column is None
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None

        counts: dict[str, int] = {}
        for row in sheet.rows:
            raw_identifier = row.value(identifier_column)
            raw_name = row.value(name_column)
            raw_timestamp = row.value(timestamp_column)
            raw_device = row.value(device_column)
            identifier_label = _normalized_identity_label(raw_identifier or "")
            employee_name = _normalized_identity_label(raw_name or "")
            if (
                identifier_label is None
                or employee_name is None
                or raw_timestamp is None
                or _parse_datetime(raw_timestamp) is None
                or raw_device is None
                or _normalized_device_label(raw_device) is None
            ):
                return None

            identifier_key = re.sub(r"\s+", "", identifier_label.casefold())
            name_key = re.sub(r"\s+", "", employee_name.casefold())
            previous_name = identifier_to_name.setdefault(identifier_key, name_key)
            previous_identifier = name_to_identifier.setdefault(name_key, identifier_key)
            if previous_name != name_key or previous_identifier != identifier_key:
                return None

            identifier_labels.setdefault(identifier_key, identifier_label)
            employee_names.setdefault(identifier_key, employee_name)
            counts[identifier_key] = counts.get(identifier_key, 0) + 1
            total_counts[identifier_key] = total_counts.get(identifier_key, 0) + 1

        sheet_counts.append((sheet, identifier_column, name_column, timestamp_column, counts))
        total_scanned += len(sheet.rows)

    if not total_counts or total_scanned <= 0:
        return None
    highest_count = max(total_counts.values())
    winner_keys = tuple(
        sorted(
            (key for key, count in total_counts.items() if count == highest_count),
            key=lambda key: (
                re.sub(r"\s+", "", employee_names[key].casefold()),
                key,
            ),
        )
    )
    if not winner_keys or len(winner_keys) > _MAX_TABLE_ROWS:
        return None

    coverages = [
        _EmployeeFrequencyCoverage(
            entry=sheet.rows[0].entry,
            sheet=sheet.rows[0].sheet,
            identifier_column=identifier_column,
            name_column=name_column,
            timestamp_column=timestamp_column,
            first_row=sheet.rows[0].number,
            last_row=sheet.rows[-1].number,
            scanned_rows=len(sheet.rows),
            counts=tuple(
                (
                    key,
                    identifier_labels[key],
                    employee_names[key],
                    count,
                )
                for key, count in sorted(
                    counts.items(),
                    key=lambda item: (
                        re.sub(r"\s+", "", employee_names[item[0]].casefold()),
                        item[0],
                    ),
                )
            ),
        )
        for sheet, identifier_column, name_column, timestamp_column, counts in sheet_counts
    ]
    hits = _build_employee_frequency_hits(
        coverages,
        frozenset(winner_keys),
        total_employee_count=len(total_counts),
    )
    if hits is None or not hits:
        return None

    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    safe_title = _citation_safe_text(title)
    identifier_label = "人员工号" if identifier_kind == "employee_id" else "卡号"
    citation = _citation_marker(hits)
    if len(winner_keys) == 1:
        winner_key = winner_keys[0]
        answer = (
            f"在《{safe_title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"打卡总次数最多的员工是“{_citation_safe_text(employee_names[winner_key])}”，"
            f"共打卡 {highest_count} 次。{citation}"
        )
    else:
        displayed_winners = "、".join(
            f"“{_citation_safe_text(employee_names[key])}”"
            f"（{identifier_label}：{_citation_safe_text(identifier_labels[key])}）"
            for key in winner_keys
        )
        answer = (
            f"在《{safe_title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"打卡总次数最多的员工有 {len(winner_keys)} 位，并列第一："
            f"{displayed_winners}，各打卡 {highest_count} 次。{citation}"
        )

    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="员工打卡频次",
            columns=(identifier_label, "员工姓名", "打卡次数"),
            rows=tuple(
                (
                    _citation_safe_text(identifier_labels[key]),
                    _citation_safe_text(employee_names[key]),
                    f"{highest_count} 次",
                )
                for key in winner_keys
            ),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_device_frequency(sheets: tuple[_Sheet, ...], question: str) -> SpreadsheetAnswer | None:
    if _has_unsupported_device_frequency_scope(question):
        return None

    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        timestamp_shape = "timestamp" in sheet.columns
        device_shape = "device" in sheet.columns
        identity_shape = any(
            kind in sheet.columns
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        attendance_shape_signals = sum((timestamp_shape, device_shape, identity_shape))
        partial_attendance_shape = (
            timestamp_shape or device_shape
        ) and attendance_shape_signals >= 2
        if not partial_attendance_shape:
            continue
        if not (timestamp_shape and device_shape and identity_shape):
            return None
        timestamp_signal = (
            sheet.columns.get("timestamp") is not None and "timestamp" not in sheet.ambiguous
        )
        identity_signal = any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        if timestamp_shape and identity_shape and not (timestamp_signal and identity_signal):
            return None
        if not (timestamp_signal and identity_signal):
            continue
        device_column = sheet.columns.get("device")
        if not device_shape or device_column is None or "device" in sheet.ambiguous:
            return None
        attendance_sheets.append(sheet)
    if not attendance_sheets:
        return None

    total_counts: dict[str, int] = {}
    display_labels: dict[str, str] = {}
    coverages: list[_DeviceFrequencyCoverage] = []
    total_scanned = 0
    for sheet in attendance_sheets:
        device_column = sheet.columns.get("device")
        timestamp_column = sheet.columns.get("timestamp")
        identity_columns = tuple(
            column
            for kind in ("employee_id", "card_number", "employee_name", "department")
            if kind not in sheet.ambiguous and (column := sheet.columns.get(kind)) is not None
        )
        if (
            device_column is None
            or timestamp_column is None
            or not identity_columns
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None

        sheet_counts: dict[str, int] = {}
        for row in sheet.rows:
            raw_timestamp = row.value(timestamp_column)
            raw_device = row.value(device_column)
            if (
                raw_timestamp is None
                or _parse_datetime(raw_timestamp) is None
                or raw_device is None
                or not any((row.value(column) or "").strip() for column in identity_columns)
            ):
                return None
            normalized_device = _normalized_device_label(raw_device)
            if normalized_device is None:
                return None
            device_key, display_label = normalized_device
            display_labels.setdefault(device_key, display_label)
            sheet_counts[device_key] = sheet_counts.get(device_key, 0) + 1
            total_counts[device_key] = total_counts.get(device_key, 0) + 1

        coverages.append(
            _DeviceFrequencyCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                column=device_column,
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                counts=tuple(
                    (key, display_labels[key], count)
                    for key, count in sorted(
                        sheet_counts.items(),
                        key=lambda item: (
                            display_labels[item[0]].casefold(),
                            display_labels[item[0]],
                        ),
                    )
                ),
            )
        )
        total_scanned += len(sheet.rows)

    if not total_counts or total_scanned <= 0:
        return None
    highest_count = max(total_counts.values())
    winner_keys = tuple(
        sorted(
            (key for key, count in total_counts.items() if count == highest_count),
            key=lambda key: (display_labels[key].casefold(), display_labels[key]),
        )
    )
    if not winner_keys or len(winner_keys) > _MAX_TABLE_ROWS:
        return None
    hits = _build_device_frequency_hits(coverages, frozenset(winner_keys))
    if hits is None or not hits:
        return None

    citation = _citation_marker(hits)
    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    safe_title = _citation_safe_text(title)
    winner_labels = tuple(display_labels[key] for key in winner_keys)
    if len(winner_labels) == 1:
        answer = (
            f"在《{safe_title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"使用最频繁的设备是“{_citation_safe_text(winner_labels[0])}”，"
            f"共记录 {highest_count} 次。{citation}"
        )
    else:
        displayed_winners = "、".join(f"“{_citation_safe_text(label)}”" for label in winner_labels)
        answer = (
            f"在《{safe_title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"使用最频繁的设备有 {len(winner_labels)} 个，并列第一：{displayed_winners}，"
            f"各记录 {highest_count} 次。{citation}"
        )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="闸机设备使用频率",
            columns=("设备名称", "打卡次数"),
            rows=tuple((display_labels[key], f"{highest_count} 次") for key in winner_keys),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _normalized_device_label(value: str) -> tuple[str, str] | None:
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        return None
    display_label = re.sub(r"\s+", " ", normalized).strip()
    device_key = display_label.casefold()
    if (
        not display_label
        or len(display_label) > _MAX_LABEL_CHARACTERS
        or device_key in _MISSING_DEVICE_LABELS
    ):
        return None
    return device_key, display_label


def _citation_safe_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    without_controls = "".join(
        " " if character.isspace() else character
        for character in normalized
        if character.isspace() or not unicodedata.category(character).startswith("C")
    )
    single_line = " ".join(without_controls.split())
    numeric_markers_sanitized = _CITATION_LIKE_PATTERN.sub(
        lambda match: f"［{match.group(0)[1:-1].strip()}］",
        single_line,
    )
    return numeric_markers_sanitized.replace("[", "［").replace("]", "］")


def _answer_event_result_existence(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    semantic_question = _normalize_event_result_query_aliases(
        _strip_spreadsheet_filename_mentions(question)
    )
    terms = _event_result_terms(semantic_question)
    if not terms or len(terms) > _MAX_TABLE_ROWS:
        return None

    total_counts = {term: 0 for term in terms}
    coverages: list[_EventResultCoverage] = []
    total_scanned = 0
    total_matches = 0
    attendance_sheets: list[_Sheet] = []
    for sheet in sheets:
        result_column = sheet.columns.get("event_result")
        timestamp_signal = (
            sheet.columns.get("timestamp") is not None and "timestamp" not in sheet.ambiguous
        )
        device_signal = sheet.columns.get("device") is not None and "device" not in sheet.ambiguous
        identity_signal = any(
            sheet.columns.get(kind) is not None and kind not in sheet.ambiguous
            for kind in ("employee_id", "card_number", "employee_name", "department")
        )
        attendance_signal = timestamp_signal and device_signal and identity_signal
        if result_column is None or "event_result" in sheet.ambiguous:
            if attendance_signal:
                return None
            continue
        if not attendance_signal:
            continue
        attendance_sheets.append(sheet)
    if not attendance_sheets or _has_unsupported_event_result_scope(semantic_question, terms):
        return None

    for sheet in attendance_sheets:
        result_column = sheet.columns.get("event_result")
        if (
            result_column is None
            or "event_result" in sheet.ambiguous
            or not sheet.rows
            or any(not row.entry.integrity_metadata for row in sheet.rows)
        ):
            return None
        sheet_counts = {term: 0 for term in terms}
        matched_rows: list[int] = []
        for row in sheet.rows:
            raw_result = row.value(result_column)
            if raw_result is None or not raw_result.strip():
                return None
            row_matched = False
            for term in terms:
                if _event_result_matches(raw_result, term):
                    sheet_counts[term] += 1
                    total_counts[term] += 1
                    row_matched = True
            if row_matched:
                matched_rows.append(row.number)
        coverages.append(
            _EventResultCoverage(
                entry=sheet.rows[0].entry,
                sheet=sheet.rows[0].sheet,
                column=result_column,
                first_row=sheet.rows[0].number,
                last_row=sheet.rows[-1].number,
                scanned_rows=len(sheet.rows),
                counts=tuple((term, sheet_counts[term]) for term in terms),
                matched_rows=tuple(matched_rows),
            )
        )
        total_scanned += len(sheet.rows)
        total_matches += len(matched_rows)

    if not coverages or total_scanned <= 0:
        return None
    hits = _build_event_result_hits(coverages)
    if hits is None or not hits:
        return None
    citation = _citation_marker(hits)
    titles = {coverage.entry.title for coverage in coverages}
    title = next(iter(titles)) if len(titles) == 1 else "选定考勤工作簿"
    requested = "或".join(f"“{term}”" for term in terms)
    count_summary = "、".join(f"“{term}”{total_counts[term]} 条" for term in terms)
    if total_matches:
        answer = (
            f"有。在《{title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"共发现 {total_matches} 条符合{requested}条件的记录；"
            f"其中{count_summary}。{citation}"
        )
    else:
        answer = (
            f"没有。在《{title}》中已完整扫描 {total_scanned} 条打卡记录，"
            f"未发现{requested}记录，共 0 条；其中{count_summary}。{citation}"
        )
    return SpreadsheetAnswer(
        answer=answer,
        table=SpreadsheetTable(
            title="异常打卡记录核验",
            columns=("检查条件", "匹配数量", "结论"),
            rows=tuple(
                (
                    term,
                    f"{total_counts[term]} 条",
                    "已发现" if total_counts[term] else "未发现",
                )
                for term in terms
            ),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _has_unsupported_event_result_scope(question: str, terms: tuple[str, ...]) -> bool:
    residual = question
    for term in sorted(terms, key=len, reverse=True):
        residual = residual.replace(term, "")
    for phrase in _EVENT_RESULT_NEUTRAL_PHRASES:
        residual = residual.replace(phrase, "")
    return bool(_EVENT_RESULT_RESIDUAL_PATTERN.sub("", residual))


def _answer_employee_field(
    sheets: tuple[_Sheet, ...], question: str, *, field: str, field_label: str
) -> SpreadsheetAnswer | None:
    names = {
        value
        for sheet in sheets
        if (column := sheet.columns.get("employee_name")) is not None
        for row in sheet.rows
        if (value := row.value(column))
    }
    target_name = _mentioned_value(names, question)
    if target_name is None or len(target_name) > _MAX_LABEL_CHARACTERS:
        return None
    records: list[tuple[str, _Row]] = []
    incomplete = False
    for sheet in sheets:
        name_column = sheet.columns.get("employee_name")
        if name_column is None:
            continue
        matching_rows = [row for row in sheet.rows if row.value(name_column) == target_name]
        if not matching_rows:
            continue
        value_column = sheet.columns.get(field)
        if value_column is None or field in sheet.ambiguous:
            incomplete = True
            continue
        for row in matching_rows:
            value = row.value(value_column)
            if value:
                records.append((value, row))
            else:
                incomplete = True
    values = {value for value, _ in records}
    if incomplete or len(values) != 1:
        return None
    value = next(iter(values))
    evidence = [min((row for _, row in records), key=_row_sort_key)]
    hits = _build_hits(evidence)
    if hits is None:
        return None
    citations = _citation_marker(hits)
    return SpreadsheetAnswer(
        answer=f"员工“{target_name}”的{field_label}是 {value}。{citations}",
        table=SpreadsheetTable(
            title="员工信息",
            columns=("员工姓名", field_label),
            rows=((target_name, value),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_department_employees(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    if _question_date(question) is not None or _has_unconsumed_attendance_scope(
        sheets,
        question,
        allowed_fields=frozenset({"department"}),
    ):
        return None
    departments = {
        value
        for sheet in sheets
        if (column := sheet.columns.get("department")) is not None
        for row in sheet.rows
        if (value := row.value(column))
    }
    department = _mentioned_value(departments, question)
    if department is None or len(department) > _MAX_LABEL_CHARACTERS:
        return None
    by_identity: dict[tuple[str | None, str], list[_Row]] = {}
    identifiers_by_name: dict[str, set[str]] = {}
    names_with_missing_identifier: set[str] = set()
    names_by_identifier: dict[str, set[str]] = {}
    incomplete = False
    for sheet in sheets:
        department_column = sheet.columns.get("department")
        if department_column is None:
            continue
        matching_rows = [row for row in sheet.rows if row.value(department_column) == department]
        if not matching_rows:
            continue
        name_column = sheet.columns.get("employee_name")
        employee_id_column = sheet.columns.get("employee_id")
        if name_column is None or "employee_name" in sheet.ambiguous:
            incomplete = True
            continue
        for row in matching_rows:
            name = row.value(name_column)
            if not name:
                incomplete = True
                continue
            if len(name) > _MAX_LABEL_CHARACTERS:
                incomplete = True
                continue
            employee_id = row.value(employee_id_column)
            if employee_id:
                identifiers_by_name.setdefault(name, set()).add(employee_id)
                names_by_identifier.setdefault(employee_id, set()).add(name)
            else:
                names_with_missing_identifier.add(name)
            by_identity.setdefault((employee_id, name), []).append(row)
    if (
        incomplete
        or not by_identity
        or len(by_identity) > _MAX_TABLE_ROWS
        or any(len(names) > 1 for names in names_by_identifier.values())
        or any(name in identifiers_by_name for name in names_with_missing_identifier)
    ):
        return None
    identities = tuple(
        sorted(
            by_identity,
            key=lambda identity: (identity[0] is None, identity[0] or "", identity[1]),
        )
    )
    evidence = [min(by_identity[identity], key=_row_sort_key) for identity in identities]
    hits = _build_hits(evidence)
    if hits is None:
        return None
    citations = _citation_marker(hits)
    display_names = tuple(
        f"{name}（{employee_id}）" if employee_id else name for employee_id, name in identities
    )
    return SpreadsheetAnswer(
        answer=(
            f"{department}在考勤记录中共有 {len(identities)} 位员工："
            f"{'、'.join(display_names)}。{citations}"
        ),
        table=SpreadsheetTable(
            title=f"{department}考勤员工",
            columns=("人员工号", "员工姓名"),
            rows=tuple((employee_id or "—", name) for employee_id, name in identities),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_time_range(sheets: tuple[_Sheet, ...], question: str) -> SpreadsheetAnswer | None:
    if (
        _question_date(question) is not None
        or _has_relative_time_scope(question)
        or _has_unconsumed_attendance_scope(sheets, question)
    ):
        return None
    records, invalid = _timestamp_records(sheets)
    if invalid or not records:
        return None
    earliest = min(
        records,
        key=lambda item: (item.timestamp or datetime.max, _row_sort_key(item.row)),
    )
    latest = max(
        records,
        key=lambda item: (item.timestamp or datetime.min, _row_sort_key(item.row)),
    )
    assert earliest.timestamp is not None and latest.timestamp is not None
    evidence = [earliest.row] if earliest.row == latest.row else [earliest.row, latest.row]
    hits = _build_hits(evidence)
    if hits is None:
        return None
    citations = _citation_marker(hits)
    start = _format_date(earliest.timestamp.date())
    end = _format_date(latest.timestamp.date())
    return SpreadsheetAnswer(
        answer=f"这份考勤记录的日期范围是 {start}至{end}。{citations}",
        table=SpreadsheetTable(
            title="考勤记录时间范围",
            columns=("起始日期", "结束日期"),
            rows=((start, end),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_earliest_record(
    sheets: tuple[_Sheet, ...], question: str
) -> SpreadsheetAnswer | None:
    if _question_date(question) is not None or _has_unconsumed_attendance_scope(sheets, question):
        return None
    records, invalid = _timestamp_records(sheets)
    if invalid or not records:
        return None
    earliest_time = min(record.timestamp for record in records if record.timestamp is not None)
    earliest = [record for record in records if record.timestamp == earliest_time]
    resolved: list[tuple[str, str, str | None, _Row]] = []
    incomplete = False
    for record in earliest:
        name_column = record.sheet.columns.get("employee_name")
        device_column = record.sheet.columns.get("device")
        department_column = record.sheet.columns.get("department")
        name = record.row.value(name_column)
        device = record.row.value(device_column)
        department = record.row.value(department_column)
        if (
            name_column is None
            or device_column is None
            or "employee_name" in record.sheet.ambiguous
            or "device" in record.sheet.ambiguous
            or not name
            or not device
            or len(name) > _MAX_LABEL_CHARACTERS
        ):
            incomplete = True
            continue
        resolved.append((name, device, department, record.row))
    identities = {(name, device, department) for name, device, department, _ in resolved}
    if incomplete or len(identities) != 1:
        return None
    name, device, department = next(iter(identities))
    row = min((item[3] for item in resolved), key=_row_sort_key)
    hits = _build_hits([row])
    if hits is None:
        return None
    citations = _citation_marker(hits)
    assert earliest_time is not None
    timestamp_text = earliest_time.strftime("%Y-%m-%d %H:%M:%S")
    department_text = f"（{_citation_safe_text(department)}）" if department else ""
    return SpreadsheetAnswer(
        answer=(
            f"全表最早一条打卡记录发生于 {timestamp_text}，由"
            f"{department_text}员工“{_citation_safe_text(name)}”通过"
            f"“{_citation_safe_text(device)}”完成。{citations}"
        ),
        table=SpreadsheetTable(
            title="全表最早打卡记录",
            columns=("时间", "部门", "员工姓名", "设备"),
            rows=((timestamp_text, department or "—", name, device),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _answer_latest_record(sheets: tuple[_Sheet, ...], question: str) -> SpreadsheetAnswer | None:
    target_date = _question_date(question)
    if _has_unconsumed_attendance_scope(sheets, question):
        return None
    records, invalid = _timestamp_records(sheets, target_date=target_date)
    if invalid or not records:
        return None
    if target_date is None and _has_relative_time_scope(question):
        record_dates = {
            record.timestamp.date() for record in records if record.timestamp is not None
        }
        if len(record_dates) != 1:
            return None
    latest_time = max(record.timestamp for record in records if record.timestamp is not None)
    latest = [record for record in records if record.timestamp == latest_time]
    resolved: list[tuple[str, str, _Row]] = []
    incomplete = False
    for record in latest:
        name_column = record.sheet.columns.get("employee_name")
        device_column = record.sheet.columns.get("device")
        name = record.row.value(name_column)
        device = record.row.value(device_column)
        if (
            name_column is None
            or device_column is None
            or "employee_name" in record.sheet.ambiguous
            or "device" in record.sheet.ambiguous
            or not name
            or not device
            or len(name) > _MAX_LABEL_CHARACTERS
        ):
            incomplete = True
            continue
        resolved.append((name, device, record.row))
    identities = {(name, device) for name, device, _ in resolved}
    if incomplete or len(identities) != 1:
        return None
    name, device = next(iter(identities))
    row = min((item[2] for item in resolved), key=_row_sort_key)
    hits = _build_hits([row])
    if hits is None:
        return None
    citations = _citation_marker(hits)
    assert latest_time is not None
    time_text = latest_time.strftime("%H时%M分")
    resolved_date = target_date or latest_time.date()
    date_text = _format_date(resolved_date)
    return SpreadsheetAnswer(
        answer=f"{date_text}当天最晚一条打卡记录是{name}，于{time_text}通过“{device}”。{citations}",
        table=SpreadsheetTable(
            title="当日最晚打卡记录",
            columns=("日期", "时间", "员工姓名", "设备"),
            rows=((date_text, time_text, name, device),),
            citation_numbers=tuple(range(1, len(hits) + 1)),
        ),
        hits=hits,
    )


def _timestamp_records(
    sheets: tuple[_Sheet, ...], *, target_date: date | None = None
) -> tuple[list[_Record], bool]:
    records: list[_Record] = []
    invalid = False
    for sheet in sheets:
        timestamp_column = sheet.columns.get("timestamp")
        if timestamp_column is None or "timestamp" in sheet.ambiguous:
            continue
        for row in sheet.rows:
            raw = row.value(timestamp_column)
            if not raw:
                continue
            parsed = _parse_datetime(raw)
            if parsed is None:
                invalid = True
                continue
            if target_date is None or parsed.date() == target_date:
                records.append(_Record(row=row, sheet=sheet, timestamp=parsed))
    return records, invalid


def _build_event_result_hits(
    coverages: list[_EventResultCoverage],
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_EventResultCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchors: list[str] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchor = _column_range(
                coverage.sheet,
                coverage.column,
                coverage.first_row,
                coverage.last_row,
            )
            anchors.append(anchor)
            counts = "、".join(f"“{term}”{count} 条" for term, count in coverage.counts)
            matched_rows = ""
            if coverage.matched_rows:
                displayed = "、".join(str(row) for row in coverage.matched_rows[:50])
                omitted = len(coverage.matched_rows) - 50
                suffix = f"，另有 {omitted} 行" if omitted > 0 else ""
                matched_rows = f"；命中行：{displayed}{suffix}"
            summaries.append(
                f"确定性全量统计 [{anchor}]：完整扫描 {coverage.scanned_rows} 条打卡记录；"
                f"{counts}{matched_rows}。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        combined_anchor = _combined_coverage_anchor(anchors)
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(entry.source_path, combined_anchor),
                format_version=(
                    _citation_safe_text(entry.format_version) if entry.format_version else None
                ),
            )
        )
    return tuple(hits)


def _build_device_frequency_hits(
    coverages: list[_DeviceFrequencyCoverage],
    winner_keys: frozenset[str],
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_DeviceFrequencyCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchors: list[str] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchor = _column_range(
                coverage.sheet,
                coverage.column,
                coverage.first_row,
                coverage.last_row,
            )
            anchors.append(anchor)
            winner_counts = "、".join(
                f"“{display_label}”{count} 条"
                for key, display_label, count in coverage.counts
                if key in winner_keys
            )
            if not winner_counts:
                winner_counts = "本工作表无最高频设备记录"
            summaries.append(
                f"确定性全量聚合 [{anchor}]：完整扫描 {coverage.scanned_rows} 条打卡记录；"
                f"共 {len(coverage.counts)} 个设备；全局最高频设备在本表的记录数："
                f"{winner_counts}。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(
                    entry.source_path,
                    _combined_coverage_anchor(anchors),
                ),
                format_version=(
                    _citation_safe_text(entry.format_version) if entry.format_version else None
                ),
            )
        )
    return tuple(hits)


def _build_employee_frequency_hits(
    coverages: list[_EmployeeFrequencyCoverage],
    winner_keys: frozenset[str],
    *,
    total_employee_count: int,
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_EmployeeFrequencyCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchor_groups: list[tuple[str, ...]] = []
        winner_counts: dict[str, int] = {}
        winner_identifiers: dict[str, str] = {}
        winner_names: dict[str, str] = {}
        scanned_rows = 0
        for coverage in entry_coverages:
            identifier_anchor = _column_range(
                coverage.sheet,
                coverage.identifier_column,
                coverage.first_row,
                coverage.last_row,
            )
            name_anchor = _column_range(
                coverage.sheet,
                coverage.name_column,
                coverage.first_row,
                coverage.last_row,
            )
            timestamp_anchor = _column_range(
                coverage.sheet,
                coverage.timestamp_column,
                coverage.first_row,
                coverage.last_row,
            )
            anchor_groups.append((identifier_anchor, name_anchor, timestamp_anchor))
            scanned_rows += coverage.scanned_rows
            for key, identifier, name, count in coverage.counts:
                if key not in winner_keys:
                    continue
                winner_counts[key] = winner_counts.get(key, 0) + count
                winner_identifiers.setdefault(key, identifier)
                winner_names.setdefault(key, name)

        displayed_counts = "、".join(
            f"“{_citation_safe_text(winner_names[key])}”"
            f"（{_citation_safe_text(winner_identifiers[key])}）{winner_counts[key]} 条"
            for key in sorted(
                winner_counts,
                key=lambda item: (
                    re.sub(r"\s+", "", winner_names[item].casefold()),
                    item,
                ),
            )
        )
        if not displayed_counts:
            displayed_counts = "本来源无全局最高频员工记录"
        combined_anchor = _combined_grouped_coverage_anchor(anchor_groups)
        excerpt = (
            f"确定性全量聚合 [{combined_anchor}]：完整扫描 {scanned_rows} 条打卡记录；"
            f"共 {total_employee_count} 位员工；全局最高频员工在本来源的记录数："
            f"{displayed_counts}。"
        )
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(entry.source_path, combined_anchor),
                format_version=(
                    _citation_safe_text(entry.format_version) if entry.format_version else None
                ),
            )
        )
    return tuple(hits)


def _build_department_summary_hits(
    coverages: list[_DepartmentSummaryCoverage],
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_DepartmentSummaryCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchors: list[str] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            anchor = _column_range(
                coverage.sheet,
                coverage.column,
                coverage.first_row,
                coverage.last_row,
            )
            anchors.append(anchor)
            departments = "、".join(
                _citation_safe_text(department) for department in coverage.departments
            )
            summaries.append(
                f"确定性全量去重 [{anchor}]：完整扫描 {coverage.scanned_rows} 条考勤记录；"
                f"识别出 {len(coverage.departments)} 个不同部门：{departments}。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(
                    entry.source_path,
                    _combined_coverage_anchor(anchors),
                ),
                format_version=entry.format_version,
            )
        )
    return tuple(hits)


def _build_department_record_count_hits(
    coverages: list[_DepartmentRecordCountCoverage],
    target_department: str,
) -> tuple[KnowledgeSearchHit, ...] | None:
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    grouped: dict[UUID, list[_DepartmentRecordCountCoverage]] = {}
    for coverage in coverages:
        grouped.setdefault(coverage.entry.id, []).append(coverage)
    safe_department = _citation_safe_text(target_department)
    for entry_coverages in grouped.values():
        entry = entry_coverages[0].entry
        anchor_groups: list[tuple[str, str]] = []
        summaries: list[str] = []
        for coverage in entry_coverages:
            department_anchor = _column_range(
                coverage.sheet,
                coverage.department_column,
                coverage.first_row,
                coverage.last_row,
            )
            timestamp_anchor = _column_range(
                coverage.sheet,
                coverage.timestamp_column,
                coverage.first_row,
                coverage.last_row,
            )
            anchor_groups.append((department_anchor, timestamp_anchor))
            summaries.append(
                f"确定性全量筛选 [{department_anchor}, {timestamp_anchor}]："
                f"完整扫描 {coverage.scanned_rows} 条考勤记录；"
                f"“{safe_department}”命中 {coverage.matched_rows} 条。"
            )
        excerpt = "\n".join(summaries)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=_citation_safe_text(entry.title),
                excerpt=excerpt,
                source_path=_anchored_source_path(
                    entry.source_path,
                    _combined_grouped_coverage_anchor(anchor_groups),
                ),
                format_version=(
                    _citation_safe_text(entry.format_version) if entry.format_version else None
                ),
            )
        )
    return tuple(hits)


def _build_hits(rows: list[_Row]) -> tuple[KnowledgeSearchHit, ...] | None:
    unique_rows = {(row.entry.id, row.sheet, row.number): row for row in rows}
    grouped: dict[UUID, list[_Row]] = {}
    for row in sorted(unique_rows.values(), key=_row_sort_key):
        grouped.setdefault(row.entry.id, []).append(row)
    hits: list[KnowledgeSearchHit] = []
    evidence_characters = 0
    for entry_rows in grouped.values():
        entry = entry_rows[0].entry
        source_path = _evidence_source_path(entry.source_path, entry_rows)
        excerpt = "\n".join(row.excerpt for row in entry_rows)
        evidence_characters += len(excerpt)
        if evidence_characters > _MAX_EVIDENCE_CHARACTERS:
            return None
        hits.append(
            KnowledgeSearchHit(
                entry_id=entry.id,
                source_file_id=entry.source_file_id,
                title=entry.title,
                excerpt=excerpt,
                source_path=source_path,
                format_version=entry.format_version,
            )
        )
    return tuple(hits)


def _evidence_source_path(base_path: str | None, rows: list[_Row]) -> str:
    locations = [_row_range(row) for row in rows]
    selected: list[str] = []
    for location in locations:
        candidate = ",".join((*selected, location))
        if len(candidate) > _MAX_SOURCE_PATH_CHARACTERS // 2:
            break
        selected.append(location)
    omitted = len(locations) - len(selected)
    suffix = f",...(+{omitted} rows)" if omitted else ""
    evidence_path = f"{','.join(selected)}{suffix}"
    if not base_path:
        return evidence_path[:_MAX_SOURCE_PATH_CHARACTERS]
    base_path = _safe_source_path_base(base_path)
    base_budget = max(0, _MAX_SOURCE_PATH_CHARACTERS - len(evidence_path) - 1)
    return f"{base_path[:base_budget]}#{evidence_path}"


def _column_range(sheet: str, column: str, first_row: int, last_row: int) -> str:
    start = f"{column}{first_row}"
    end = f"{column}{last_row}"
    cell_range = start if start == end else f"{start}:{end}"
    return f"worksheet:{sheet}!{cell_range}"


def _anchored_source_path(base_path: str | None, anchor: str) -> str:
    if not base_path:
        return anchor[:_MAX_SOURCE_PATH_CHARACTERS]
    base_path = _safe_source_path_base(base_path)
    base_budget = max(0, _MAX_SOURCE_PATH_CHARACTERS - len(anchor) - 1)
    return f"{base_path[:base_budget]}#{anchor}"


def _safe_source_path_base(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    without_controls = "".join(
        character for character in normalized if not unicodedata.category(character).startswith("C")
    )
    return (
        without_controls.replace("%", "%25")
        .replace("#", "%23")
        .replace("[", "%5B")
        .replace("]", "%5D")
    )


def _combined_coverage_anchor(anchors: list[str]) -> str:
    selected: list[str] = []
    for anchor in anchors:
        candidate = ",".join((*selected, anchor))
        if len(candidate) > _MAX_SOURCE_PATH_CHARACTERS // 2:
            break
        selected.append(anchor)
    omitted = len(anchors) - len(selected)
    suffix = f",...(+{omitted} sheets)" if omitted else ""
    return f"{','.join(selected)}{suffix}"


def _combined_grouped_coverage_anchor(
    anchor_groups: Sequence[Sequence[str]],
) -> str:
    selected: list[str] = []
    for anchor_group in anchor_groups:
        grouped_anchor = ",".join(anchor_group)
        candidate = ",".join((*selected, grouped_anchor))
        if len(candidate) > _MAX_SOURCE_PATH_CHARACTERS // 2:
            break
        selected.append(grouped_anchor)
    omitted = len(anchor_groups) - len(selected)
    suffix = f",...(+{omitted} sheets)" if omitted else ""
    return f"{','.join(selected)}{suffix}"


def _row_range(row: _Row) -> str:
    start = f"{row.cells[0].column}{row.number}"
    end = f"{row.cells[-1].column}{row.number}"
    cell_range = start if start == end else f"{start}:{end}"
    return f"worksheet:{row.sheet}!{cell_range}"


def _mentioned_value(values: set[str], question: str) -> str | None:
    matches = [value for value in values if value and value in question]
    if not matches:
        return None
    longest = max(len(value) for value in matches)
    best = {value for value in matches if len(value) == longest}
    return next(iter(best)) if len(best) == 1 else None


def _has_unconsumed_attendance_scope(
    sheets: tuple[_Sheet, ...],
    question: str,
    *,
    allowed_fields: frozenset[str] = frozenset(),
) -> bool:
    """Reject exact data filters that an executor did not explicitly consume.

    A deterministic answer is unsafe when a department, employee, device, or
    result value appears in the question but the selected executor would scan
    the whole workbook.  Values are resolved from the trusted workbook instead
    of a hard-coded organization dictionary.
    """

    semantic_question = unicodedata.normalize(
        "NFKC", _strip_spreadsheet_filename_mentions(question)
    ).casefold()
    fields = (
        "department",
        "employee_name",
        "employee_id",
        "card_number",
        "device",
        "event_result",
    )
    for field in fields:
        if field in allowed_fields:
            continue
        for sheet in sheets:
            column = sheet.columns.get(field)
            if column is None or field in sheet.ambiguous:
                continue
            for row in sheet.rows:
                raw_value = row.value(column)
                normalized_value = _normalized_identity_label(raw_value or "")
                if normalized_value is None:
                    continue
                value_key = normalized_value.casefold()
                compact_key = re.sub(r"\s+", "", value_key)
                if len(compact_key) >= 2 and value_key in semantic_question:
                    return True
    return "event_result" not in allowed_fields and any(
        term in semantic_question for term in _EVENT_RESULT_QUERY_TERMS
    )


def _has_relative_time_scope(question: str) -> bool:
    semantic_question = unicodedata.normalize("NFKC", question).casefold()
    return any(
        term in semantic_question
        for term in (
            "今天",
            "今日",
            "昨天",
            "昨日",
            "前天",
            "当天",
            "当日",
            "本周",
            "上周",
            "本月",
            "上月",
            "今年",
            "去年",
            "上午",
            "下午",
            "白班",
            "夜班",
        )
    )


def _normalize_header(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[\s:：_\-()/（）]+", "", normalized)


def _legacy_source_text(content: str) -> str | None:
    marker_boundary = re.search(r"(?:\A|\n\n)(?=\[worksheet:)", content)
    if marker_boundary is None:
        return None
    source_text = content[marker_boundary.end() :]
    return source_text if _CELL_PATTERN.match(source_text) is not None else None


def _valid_source_location(location: str) -> bool:
    match = _LOCATION_PATTERN.fullmatch(location)
    if match is not None:
        return (
            int(match.group("row")) <= _MAX_EXCEL_ROW
            and _column_number(match.group("column").upper()) <= _MAX_EXCEL_COLUMN
        )
    return _SHEET_LOCATION_PATTERN.fullmatch(location) is not None


def _parse_datetime(value: str) -> datetime | None:
    normalized = unicodedata.normalize("NFKC", value).strip()
    for candidate in (normalized, normalized.replace("/", "-")):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            return None
        return parsed
    match = re.fullmatch(
        r"(20\d{2})年(\d{1,2})月(\d{1,2})日(?:\s*(\d{1,2})[\u65f6:](\d{1,2})(?:[\u5206:](\d{1,2}))?秒?)?",
        normalized,
    )
    if match is None:
        return None
    year, month, day, hour, minute, second = match.groups()
    try:
        return datetime(
            int(year),
            int(month),
            int(day),
            int(hour or 0),
            int(minute or 0),
            int(second or 0),
        )
    except ValueError:
        return None


def _question_date(question: str) -> date | None:
    match = re.search(r"(20\d{2})年(\d{1,2})月(\d{1,2})日", question)
    if match is None:
        match = re.search(r"(20\d{2})[-/.](\d{1,2})[-/.](\d{1,2})", question)
    if match is None:
        return None
    try:
        return date(*(int(value) for value in match.groups()))
    except ValueError:
        return None


def _is_latest_record_question(question: str) -> bool:
    return any(
        token in question
        for token in (
            "最晚",
            "最迟",
            "最后一条",
            "最后一笔",
            "最后一次",
            "最后的",
            "最新一条",
        )
    ) and any(token in question for token in ("打卡", "考勤", "通行", "刷卡"))


def _is_earliest_record_question(question: str) -> bool:
    return any(
        token in question
        for token in (
            "最早",
            "第一条",
            "第一笔",
            "第一次",
            "最先一条",
        )
    ) and any(token in question for token in ("打卡", "考勤", "通行", "刷卡"))


def _is_time_range_question(question: str) -> bool:
    semantic_question = unicodedata.normalize("NFKC", question).casefold()
    attendance_context = any(
        token in semantic_question for token in ("考勤", "打卡", "通行", "刷卡", "数据")
    )
    range_context = any(
        token in semantic_question
        for token in (
            "时间范围",
            "日期范围",
            "日期区间",
            "时间区间",
            "从哪一天到哪一天",
            "从什么时候到什么时候",
            "起止时间",
            "起始时间",
            "起始日期",
            "截止时间",
            "截止日期",
        )
    ) or (
        any(token in semantic_question for token in ("最早", "开始", "起始"))
        and any(token in semantic_question for token in ("最晚", "结束", "截止"))
    )
    return attendance_context and range_context


def _citation_marker(hits: tuple[KnowledgeSearchHit, ...]) -> str:
    return "".join(f"[{index}]" for index in range(1, len(hits) + 1))


def _format_date(value: date) -> str:
    return f"{value.year}年{value.month}月{value.day}日"


def _column_number(column: str) -> int:
    result = 0
    for character in column:
        result = result * 26 + ord(character) - ord("A") + 1
    return result


def _row_sort_key(row: _Row) -> tuple[str, str, int]:
    return (row.entry.title, row.sheet, row.number)
