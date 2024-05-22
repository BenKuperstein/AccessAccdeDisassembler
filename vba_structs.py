import dataclasses
import enum
import typing

from construct import *

import config

SIZE_T = BytesInteger(
    4 if config.IS_32_BIT_VBA6 else 8,
    signed=False,
    swapped=True
)

SIZE_T_SIGNED = BytesInteger(
    4 if config.IS_32_BIT_VBA6 else 8,
    signed=True,
    swapped=True
)

BLK_DESC = Struct(
    "size" / Int32sl,
    "data" / If(lambda ctx: ctx.size > 0, Bytes(this.size))
)

BLK = Struct(
    "unknown1" / Int16ul,
    "unknown2_bool" / Byte,
    "unknown3_bool" / Byte,
    "blk_desc" / BLK_DESC
)

BLK_DESC32 = Struct(
    "count" / Int32ul,
    "data" / If(lambda ctx: ctx.count > 0, Bytes(this.count))
)

BLK32 = Struct(
    "unknown1" / Int32ul,
    "unknown2_bool" / Byte,
    "unknown3_bool" / Byte,
    "blk_desc" / BLK_DESC32
)

DYNBLK = Struct(
    "desc" / BLK_DESC32,
    "unkown1" / Int32ul,
    "unknown2_bool" / Byte,
    "unknown3_bool" / Byte,
    "count" / Int32ul,
    "data" / Bytes(this.count)
)

INST = Struct(
    "magic" / Byte,
    "should_be_zero" / Byte,
    "blk" / BLK,
    "unknown1" / Bytes(16),
    "guid1" / Bytes(16),
    "guid2" / Bytes(16),
    "guid3" / Bytes(16),
    "unknown2" / Int16ul,
    "unknown3" / Int16ul,
    "dyn_blk" / DYNBLK
)

Variant = Struct(
    "size" / Int16ul,
    "data" / Bytes(24)
)


def create_entry_struct(flag: Byte):
    Entry = Struct(
        "me_magic" / Bytes(2),
        "should_be_zero" / Int16ul,
        "unknown3" / Bytes(16),
        "blk" / BLK
    )
    return Entry


IMP = Struct(
    "df_magic" / Byte,
    "version" / Byte,
    "unknown1" / Int16ul,
    "blk_des1" / BLK_DESC,
    "unknown2" / Int16ul,
    "data1" / Bytes(64),
    "data2" / Bytes(64),
    "blk_des2" / BLK_DESC,
    "blk" / BLK,
    "unknown3" / Int16ul
)

TypeData = Struct(
    "blk" / BLK32,
    "unknown1" / Array(8, Int16ul),
    "unknown2" / Array(16, Int32sl),
    "unknown3" / Int16ul
)

DYN_BINDNAME = Struct(
    "count" / Int16sl,
    "data" / If(lambda ctx: ctx.count > 0, Bytes(this.count))
)

DYNTYPE_BIND = Struct(
    "unknown1" / Int16ul,
    "unknown2" / Int32ul,
    "unknown3" / Int16ul,
    "unknown4" / Int32ul,
    "unknown5" / Array(3, Int16ul),
    "unknown6" / Array(6, Int32ul),
    "bind_name" / DYN_BINDNAME
)


def create_dtmb_struct(flag: Byte):
    DTMB = Struct(
        "unknown1" / Int16ul,
        "unknown2" / IfThenElse(config.IS_32_BIT_VBA6, Int16ul, Int32ul),
        "type_data" / TypeData,
        "dyn_type_data" / DYNTYPE_BIND
    )
    return DTMB


Opcodes = Struct(
    "magic" / Int16ul,
    "should_be_1" / Int16ul,
    "count" / Int16ul,
    "data" / Bytes(this.count * 12),
    "blk" / BLK32
)

BTSRC = Struct(
    "unknown1" / Int16ul,
    "unknown2" / Int16ul,
    "unknown3" / Int16ul,
    "unknown4" / Array(26, Int16ul),
    "unknown5" / Int16ul,
    "opcodes" / Opcodes
)

Module = Struct(
    "magic" / Bytes(4),
    "flag1" / Byte,
    "imp_offset" / Int32ul,
    "unkown1_part1" / Bytes(4),
    "entry_offset" / Int32ul,
    "dtmbs_offset" / Int32ul,
    "source_table_offset" / Int32ul,
    "bt_source_offset" / Int32ul,
    # "unknown1_part2" / Bytes(28),
    # "inst" / INST,
    # "unknown2" / Byte,
    # "guid1" / Bytes(16),
    # "guid2" / Bytes(16),
    # "count" / Int16ul,
    # "contain_variants" / Int16ul,
    # "variants" / If(lambda ctx: ctx.contain_variants != 0, Array(this.count, Variant)),
    # "contain_type_info" / Int16ul,
    # "entry" / create_entry_struct(this.flag1),
    # "imp" / IMP,
    "offset" / Tell,
    "padding" / Bytes(lambda ctx: ctx.dtmbs_offset - ctx.offset),
    "dtmb" / create_dtmb_struct(this.flag1)
)

BSTR = Struct(
    "len" / Int32ul,
    "data" / If(this.len > 0, PaddedString(this.len, "utf16")),
    "unk1" / If(lambda ctx: ctx.len == 0, Int16ul)
)

Sz = Struct(
    "len_" / Int16ul,
    "data" / PaddedString(this.len_, "utf16")
)

CheckedUnicodeString = Struct(
    "len" / Int16sl,
    "data" / If(lambda ctx: ctx.len > 0, PaddedString(this.len, "utf16"))
)

Unk1Common = Struct(
    "unk1" / Sz,
    "unk2" / If(lambda ctx: ctx.unk1.data[2] != 'G', Sz),
    "unk3" / Int32ul,
    "unk4" / Int16ul,
    "unk5" / Int32ul
)

Unk1 = Struct(
    "unk1" / Unk1Common,
    "unk5" / Int16ul,
)

IntlInfo = Struct(
    "unk1" / Int32ul,
    "unk2" / Int32ul,
    "unk3" / Int16ul,
    "unk4" / Int16ul
)

Unk2 = Struct(
    "unk1" / Int16ul,
    "unk2" / Int16ul
)

ModuleEntry = Struct(
    "inner_name" / CheckedUnicodeString,
    "unk2" / CheckedUnicodeString,
    "unk3" / CheckedUnicodeString,
    "unk44" / Int16ul,
    "module_name" / CheckedUnicodeString,
    "unk5" / CheckedUnicodeString,
    "unk6" / Int16ul,
    "unk7" / Int32ul,
    "count" / Int16ul,
    "unk8" / Bytes(this.count * 8),
    "unk9" / Int32ul,
    "unk10" / Byte,
    "unk11" / Int32ul,
    "unk12" / Int16ul
)

Unk4 = Struct()

NameEntry = Struct(
    "unk5" / Int16ul,
    "unk7" / If(lambda ctx: ctx.unk5 == 0, Int16ul),
    "unk8" / If(lambda ctx: ctx.unk5 == 0, Int16ul),
    "unk9" / If(lambda ctx: ctx.unk8 and ((ctx.unk8 & 0x8000) != 0), Int16ul),
    "unk10" / If(lambda ctx: ctx.unk8 and ((ctx.unk8 & 0x8000) != 0), Int16ul),
    "unk11" / If(lambda ctx: ctx.unk8 and ((ctx.unk8 & 0x8000) != 0), Int16ul),
    "unk17" / If(lambda ctx: ctx.unk5 == 0, Bytes(this.unk8 & 0x1ff)),
    "unk14" / If(lambda ctx: ctx.unk5 & 0x8000 != 0, Int16ul),
    "unk15" / If(lambda ctx: ctx.unk5 & 0x8000 != 0, Int16ul),
    "unk16" / If(lambda ctx: ctx.unk5 & 0x8000 != 0, Int16ul),
    "unk12" / If(lambda ctx: ctx.unk5 != 0, Bytes(this.unk5 & 0x1ff)),
    "unk13" / If(lambda ctx: ctx.unk5 != 0, Int32ul)
)

NameMgr = Struct(
    "unk1" / Int16ul,
    "count" / Int16ul,
    "unk3" / Int16ul,
    "unk4" / Int32ul,
    "unk5" / Array(this.count, NameEntry)
)

GUIDMgr = Struct(
    "unk1" / BLK32,
    "unk2" / Int16ul,
    "unk3" / Int32ul
)

GTLOE = Struct(
    "unk1" / Int16ul,
    "unk2" / CheckedUnicodeString,
    "unk3" / CheckedUnicodeString,
    "unk4" / CheckedUnicodeString,
    "unk5" / Int32ul,
    "unk6" / Int16ul,
    "unk7" / Int16ul,
    "unk8" / Int32ul,
    "unk9" / Int16ul,
    "unk10" / Bytes(64),
    "unk11" / Int16ul,
    "unk12" / Int16ul,
    "unk13" / Bytes(16),
    "unk14" / Int16ul,
    "count" / Int16ul,
    "module_entries" / Array(this.count, ModuleEntry),
    "unk16" / GUIDMgr,
    "unk17" / NameMgr
)

STLIB = Struct(
    "intl_info" / IntlInfo,
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "unk5" / BSTR,
    "count1" / Int16ul,
    "unk7" / Int16ul,
    "unk8" / Array(this.count1, Unk1),
    "count2" / Int16ul,
    "unk10" / Array(this.count2, Int16ul),
    "count3" / Int16ul,
    "unk11" / Array(this.count3, Unk2),
    "gtloe" / GTLOE
)

VBA_PROJECT = Struct(
    "magic" / Int16ul,
    "version" / Int16ul,
    "unk1" / Byte,
    "unk2" / Int16ul,
    "unk3" / Byte,
    "stlib" / STLIB
)


def get_max_address():
    return 0xFFFFFFFF if config.IS_32_BIT_VBA6 else 0xFFFFFFFFFFFFFFFF


Fixup = Struct(
    "address" / SIZE_T,
    "unk2" / If(
        lambda ctx: ctx.address != get_max_address(), Int16sl),
    "srp_index" / If(lambda ctx: ctx.address != get_max_address(), Int16ul)
)

SRPModuleType = Enum(Byte, PROJECT=0, PROJECT_TYPE=1, MODULE=2, MODULE_TYPE=3)


@dataclasses.dataclass
class SRPInfo:
    type: SRPModuleType
    args: dict[str, typing.Any]


# Define EPITypeInner
EPITypeInner = Struct(
    "unk1" / Int32ul,
    "unk2" / Int32ul
)

# Define EPIType
EPIType = Struct(
    "unk1" / Int16ul,
    If(this.unk1 & 0x80,
       Struct(
           "count" / Int16ul,
           "items" / Array(this.count, EPITypeInner)
       )
       ),
    If((this.unk1 & 0x3F) == 18,
       "unk2" / Int32ul
       ),
    If((this.unk1 == 20) | (this.unk1 == 21) | (this.unk1 == 29) | (this.unk1 == 30),
       "pointer" / Fixup
       )
)

# Define ModuleTypeEntry
FunctionTypeEntry = Struct(
    "unk0" / Int16ul,
    "fixup1" / Fixup,
    "unk1" / Int32ul,
    "count" / Int16ul,
    "unk2" / Int16ul,
    "unk4" / Int16ul,
    "fixup2" / Fixup,
    "fixup3" / Fixup,
    "unk5" / Int32ul,
    "pointers" / If(lambda ctx: bool((ctx.count & 0xFC) >> 2),
                    Array((this.count & 0xFC) >> 2, Fixup)
                    ),
    "types" / Array(((this.count & 0xFC) >> 2) + 1, EPIType),
    "unk6" / Int32ul
    # Note: Handling of `if (unk6)` case is skipped as per your comment.
)

# Define ModuleTypeResourceInner
ModuleTypeResourceInner = Struct(
    "unk1" / Int16ul,
    If(this.unk1,
       Struct(
           "pointer1" / Fixup,
           "pointer2" / Fixup,
           "unk2" / Int32ul,
           "unk3" / Int32ul,
           "unk4" / Int16ul,
           "unk5" / Int16ul,
           "type" / EPIType,
           "unk6" / Int32ul,
           "unk7" / Int16ul,
           "unk8" / Int16ul
       )
       )
)


def create_module_type_resource(srp_info: SRPInfo):
    return Struct(
        "fixup1" / Fixup,
        "pointer1" / Fixup,
        "unk1" / Int32ul,
        "unk2" / Int32ul,
        "unk3" / Int32ul,
        "unk4" / Int16ul,
        "function" / Array(srp_info.args.get("func_num", 0), FunctionTypeEntry),
        "count" / Int16ul,
        "items" / If(lambda ctx: bool(ctx.count),
                     Array(this.count, ModuleTypeResourceInner)
                     ),
        "count3" / Int16ul,
        "pointers3" / If(lambda ctx: bool(ctx.count3),
                         Array(this.count3, Fixup)
                         ),
        "count4" / Int16ul,
        "pointers4" / If(lambda ctx: bool(ctx.count4),
                         Array(this.count4, Fixup)
                         )
    )


ProjectResourceModuleEntry = Struct(
    "unk" / Int32sl,
    "code_pointer" / Fixup,
    "pointer1" / Fixup,
    "pointer2" / Fixup,
    "pointer3" / If(lambda ctx: not bool(ctx.unk & 2), Fixup),
    "pointer4" / If(lambda ctx: not bool(ctx.unk & 2), Fixup),
    "count" / If(lambda ctx: bool(ctx.unk & 0x18000), Int16ul),
    "functions" / If(lambda ctx: bool(ctx.unk & 0x18000), Array(this.count, Fixup)),
    "unk2" / Int32sl,
    "name" / Fixup
)

ProjectResourceInnerEntry2 = Struct(
    "fixup" / Fixup,
    "data" / Bytes(16)
)

ProjectResource = Struct(
    "fixup1" / Fixup,
    "pointer1" / Fixup,
    "pointer2" / Fixup,
    "unk1" / Bytes(16),
    "unk2" / Int16ul,
    "locale" / Int32sl,
    "unk3" / Int16ul,
    "unk4" / Int16ul,
    "unk5" / Int32sl,
    "unk6" / Int16ul,
    "pointer3" / Fixup,
    "count" / Int16ul,
    "modules" / Array(this.count, ProjectResourceModuleEntry),
    "count2" / Int16ul,
    "entries2" / Array(this.count2, ProjectResourceInnerEntry2)
)

ModuleResourceInnerInner = Struct(
    "unk1" / Int32ul,
    "unk2" / Int32ul,
)

ModuleResourceInner = Struct(
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "unk3" / Int32ul,
    "pointer1" / Fixup,
    "pointer2" / Fixup,
    "pointer3" / Fixup,
    "unk4" / Int32ul,
    "unk5" / Int32ul,
    "unk6" / Int32ul,
    "resources" / If(lambda ctx: bool(ctx.unk1 & 0x8), Struct(
        "count" / Int16ul,
        "resources" / Array(this.count, ModuleResourceInnerInner)
    )
                     ),
    "pointer4" / Array(this.unk2, Fixup)
)


def add_dicts(*dicts: dict) -> dict:
    first_dict = dicts[0]
    for d in dicts[1:]:
        first_dict.update(d)
    return first_dict


RESDESCTBLRecord = Struct(
    "start" / Tell,
    "flag2" / Int16ul,
    "v2" / Computed(lambda ctx: 0),
    "size" / Computed(lambda ctx: 4),

    "part_a" / If(lambda ctx: ctx.flag2 & 0xf == 5,
                  Struct(
                      "unk1" / Int16ul,
                      "flag3" / Int16ul,
                      "flag4" / Int16ul,
                      If(lambda ctx: not bool(ctx._.flag2 & 0x100),
                         Computed(lambda ctx: setattr(ctx._, "size", ctx._.size + 6))),
                      If(lambda ctx: not bool(ctx._.flag2 & 0x100),
                         Computed(lambda ctx: setattr(ctx._, "v2", 32 if ctx.flag3 & 0x60 else 16))),
                  )
                  ),
    "v3" / Computed(lambda ctx: ctx.part_a.flag4 if (ctx.flag2 & 0xf) == 5 else ctx.flag2),
    "part_b" / If(lambda ctx: ctx.v2 - ctx.size > 0,
                  Struct(
                      "unk7" / Bytes(lambda ctx: ctx._.v2 - ctx._.size),
                  )
                  ),
    "kind" / Computed(lambda ctx: ctx.flag2 & 0xf),
    "v4" / Computed(lambda ctx: 6 if bool(ctx.flag2 & 0x400) else 0),
    "ret" / Computed(lambda ctx: 0),
    "kind_switch" / Switch(
        lambda ctx: ctx.kind,
        add_dicts({
            i:
                Computed(lambda ctx: setattr(ctx, "ret", 8 if bool(ctx.flag2 & 0x2000) else
                ctx.v4 if ctx.v4 > 4 else 4)
                         )
            for i in (1, 2, 3, 0xb)
        },
            {
                i: Computed(
                    lambda ctx:
                    setattr(ctx, "ret", 10)) for i in (4, 0xa)
            },
            {5:
                 IfThenElse(lambda ctx: bool(ctx.flag2 & 0x100),
                            Computed(
                                lambda ctx: setattr(
                                    ctx, "ret", 32 if ctx.v3 & 0x60 else 14 if ctx.v4 & 0xf else 10)),
                            If(lambda ctx: (((ctx.v3 & 0xf) > 0 and (ctx.v3 & 0xf) < 4) or bool(
                                ctx.v3))
                                           or (ctx.flag2 & 0x80 == 0) or ctx.flag2 & 0x2200,
                               Struct(
                                   "flag5" / Int16ul,
                                   "flag6" / Int16ul,
                                   "v7" / Computed(lambda ctx: ctx.flag5 * 8 - 8 - 4),
                                   "v8" / Computed(lambda ctx: ctx.v7 + 56 if ctx.flag5 else 56
                                   if ctx._.v3 & 0x60 else ctx.v7 + 40 if ctx.flag5 else 40),
                                   "v9" / Computed(
                                       lambda ctx: ctx.v8 + 4 if bool(ctx.flag6 & 0xe0) else ctx.v8),
                                   Computed(lambda ctx: setattr(ctx._, "ret", ctx.v9))
                               )
                               )
                            ),
             6:
                 Computed(lambda ctx: setattr(ctx, "ret", ctx.v4 if ctx.v4 > 4 else 4)),
             8:
                 Computed(lambda ctx: setattr(ctx, "ret", 8)),
             9:
                 Computed(lambda ctx: setattr(ctx, "ret", 28)),
             })
    ),
    "end" / Tell,
    "padding_size" / Computed(lambda ctx: (ctx.ret - (ctx.end - ctx.start) - 2) // 2),
    "unk3" / Array(lambda ctx: ctx.padding_size if ctx.padding_size > 0 else 0, Int16ul)
)


def get_rsedesctbl(size):
    return Struct(
        "start" / Tell,
        "unk1" / Bytes(6),
        "count" / Int16ul,
        "records" / Array(this.count, RESDESCTBLRecord),
        "end" / Tell,
        "padding_size" / Computed(lambda ctx: ctx._.shit_size - (ctx.end - ctx.start)),
        "padding" / Array(lambda ctx: (
            ctx.padding_size + 8 if ctx.padding_size == 34 else ctx.padding_size) if ctx.padding_size > 0 else 0, Byte),
        "records_extra" / Array(this.count,
                                Struct(
                                    "index" / Index,
                                    "record" / Computed(lambda ctx: ctx._.records[ctx.index]),
                                    "pointer1" / If(
                                        lambda ctx: (ctx.record.flag2 & 0xf) == 9 and bool(ctx.record.flag2 & 0x60),
                                        Fixup
                                    ),
                                    "inner" / If(lambda ctx: (ctx.record.flag2 & 0xf) == 5,
                                                 Struct(
                                                     "pointer2" / If(lambda ctx: bool(ctx._.record.unk1 & 0x60),
                                                                     Fixup),
                                                     "pointer3" / IfThenElse(
                                                         lambda ctx: (ctx._.record.flag2 & 0x100) == 0,
                                                         If(lambda ctx: (bool(ctx._.record.part_a.flag4 & 0x40)
                                                                         or bool(
                                                                     ctx._.record.part_a.flag4 & 0x20))
                                                                        and bool(
                                                             ctx._.record.unk3[1] & 0x20)
                                                                        and (bool(
                                                             ctx._.record.unk3[4] & 0x20) or bool(
                                                             ctx._.record.part_a.flag4 & 0x300))
                                                            , Fixup
                                                            ),
                                                         If(lambda ctx: bool(
                                                             ctx._.record.flag5 & 0x20) and (bool(
                                                             ctx._.record.unk3[2] & 0x20) or bool(
                                                             ctx._record.part_a.flag4 & 0x40)),
                                                            Fixup)
                                                     )
                                                 )

                                                 )

                                )
                                )
    )


RTMI = Struct(
    "data_size" / SIZE_T_SIGNED,
    "code_size" / If(lambda ctx: ctx.data_size != -1, SIZE_T_SIGNED),
    "data" / If(lambda ctx: ctx.data_size != -1, Bytes(this.data_size)),
    "pointers" / Peek(RepeatUntil(lambda x, lst, ctx: x.address > 0x1000000 or x.unk2 != 0, Fixup)),
    Bytes(lambda ctx: (8 if config.IS_32_BIT_VBA6 else 12) * (len(ctx.pointers) - 1 if ctx.pointers else 0))
)

Resource1 = Struct(
    "count" / SIZE_T,
    "data" / Bytes(this.count)
)

Resource2 = Struct(
    "count" / SIZE_T,
    "data" / Bytes(this.count)
)

Resource3 = Struct(
    "data" / Bytes(16)
)

Resource5 = Struct(
    "unk1" / Int16ul,
    "pointer1" / Fixup,
    "pointer2" / Fixup,
    "pointer3" / Fixup,
)

Resource6 = Struct(
    "pointer1" / Fixup,
    "pointer2" / Fixup,
)

Resource7 = Struct(
    "pointer1" / Fixup,
    "pointer2" / Fixup,
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "pointer3" / Fixup,
    "pointer4" / If(not config.IS_32_BIT_VBA6, Fixup),

)

Resource10 = Struct(
    "pointer1" / Fixup,
    "pointer2" / Fixup,
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "unk3" / Int32ul,
    "pointers" / Array(3, Fixup),
    "unk4" / Int32ul,
    "unk5" / Int16ul
)

Resource11 = Struct(
    "count" / Int32sl,
    "data" / If(lambda ctx: ctx.count > 0, PaddedString(this.count, "utf16"))
)
Resource12 = Struct(
    "length" / SIZE_T,
    "data" / Bytes(this.length)
)

Resource13 = Struct(
    "count" / Int16ul,
    "data" / Bytes(this.count)
)
Resource13_ = Struct(
    "size" / Int16ul,
    "content" / Bytes(this.size),
    "pointers" / Peek(RepeatUntil(lambda x, lst, ctx: x.unk2 != 0, Fixup)),
    Bytes(lambda ctx: (8 if config.IS_32_BIT_VBA6 else 12) * (len(ctx.pointers) - 1 if ctx.pointers else 0))
)

Resource14 = Struct(
    "unk1" / Byte,
    "count" / Byte,
    "unk2" / Int16ul,
    "data" / Bytes(this.count + 1),
    "pointer" / If(lambda ctx: ctx.unk1 == 3, Fixup)
)
Resource15 = Struct(
    "count" / Int16ul,
    "unk1" / Int16ul,
    "unk2" / Int32ul,
    "unk3" / Array(this.count * 2, Int32ul)
)

Resource18 = Struct(
    "unk1" / Int16ul,
    "pointer" / If(lambda ctx: not config.IS_32_BIT_VBA6, Fixup)
)

Resource19 = Struct(
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "inner" / If(not config.IS_32_BIT_VBA6,
                 Struct(
                     "pointer1" / Fixup,
                     "pointer2" / Fixup,
                 )
                 )
)

Resource20 = Struct(
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "unk3" / Int16ul,
)


def get_module_prop_a(module_flag: SIZE_T) -> int:
    if config.IS_32_BIT_VBA6:
        return (module_flag & 0xFF000000) >> 24
    else:
        return (module_flag & 0xFF00000000000000) >> 56


def get_module_prop_b(module_flag: SIZE_T) -> int:
    if config.IS_32_BIT_VBA6:
        return 4 * (module_flag & 0xFFFFFF)
    else:
        return 4 * (module_flag & 0xFFFFFFFFFFFFFF)


ModuleConditionalPart = Struct(
    "count1" / Int16ul,
    "count2" / Int16ul,
    "count3" / Int16ul,
    "count4" / Int16ul,
    "pointer1" / Fixup,
    "pointers1" / Array(this.count1, Fixup),
    "pointers2" / Array(this.count2, Fixup),
    "pointers4" / Array(2, Fixup),
    "pointers3" / Array(this.count3, Fixup),
    "module_resources" / Array(this.count4, ModuleResourceInner),
    "unk4" / Int16ul,
    "unk5" / Int16ul,
    "count5" / Int16ul,
    "unk6" / Int16ul,
    "pointers4" / Array(this.count5, Fixup),
)


def get_module_resource(info: SRPInfo):
    return Struct(
        "pointer1" / Fixup,
        "type_info" / Fixup,
        "pointer2" / Fixup,
        "unk1" / Int16ul,
        "unk2" / Int16ul,
        "num_imports" / Int16ul,
        "unk3" / Int16ul,
        "imports" / Array(this.num_imports, Fixup),
        "conditional" / If(info.args.get("module_flag", 0) & 0x2, ModuleConditionalPart),
        "rtmis" / Array(info.args.get("func_num", 0), RTMI)
    )


def get_srp_resource(module_flag: SIZE_T, srp_info: SRPInfo):
    prop_a = get_module_prop_a(module_flag)
    prop_b = get_module_prop_b(module_flag)
    SRPResource = Struct(
        "resource" / Switch(
            prop_a,
            {
                0: Switch(
                    srp_info.type,
                    {
                        SRPModuleType.PROJECT: ProjectResource,
                        SRPModuleType.MODULE: get_module_resource(srp_info),
                        SRPModuleType.MODULE_TYPE: create_module_type_resource(srp_info),
                    },
                    default=Struct()
                ),
                1: Resource1,
                2: Resource2,
                3: Resource3,
                5: Resource5,
                6: Resource6,
                7: Resource7,
                10: Resource10,
                11: Resource11,
                12: Resource12,
                13: Resource13_ if config.IS_32_BIT_VBA6 else Resource13,
                14: Resource14,
                15: Resource15,
                18: Resource18,
                19: Resource19,
                20: Resource20,
            },
            default=Struct()
        )
    )
    return SRPResource


def get_end_resource_flag():
    0x7f000000 if config.IS_32_BIT_VBA6 else 0x7F000000000000


def create_resource_wrapper(srp_info: SRPInfo):
    return Struct(
        "module_flag" / SIZE_T,
        "resource" / If(lambda ctx: ctx.module_flag != get_end_resource_flag() and ctx.module_flag != 0,
                        get_srp_resource(this._.module_flag, srp_info))
    )


def create_srp(srp_info: SRPInfo):
    SRP = Struct(
        "magic" / Int16ul,
        "unk1" / Array(4, SIZE_T),
        "data" / RepeatUntil(lambda x, lst, ctx: x == 0, SIZE_T),
        "resources" / RepeatUntil(
            lambda x, lst, ctx: x.module_flag == 0 or x.module_flag == get_end_resource_flag(),
            create_resource_wrapper(srp_info))
        # "resources" / RepeatUntil(lambda x, lst, ctx: x == 0, Byte)
    )
    return SRP


Bstr = Struct(
    "len" / Int32ul,
    "data" / If(lambda ctx: ctx.len > 0, PaddedString(this.len, "utf16")),
    "unk" / If(lambda ctx: ctx.len == 0, Int16ul)
)

SRP_ENTRY = Struct(
    "file_type" / Int16ul,
    "data" / If(lambda ctx: ctx.file_type & 4, Pass),
    "module_index" / If(lambda ctx: ctx.file_type & 4 == 0, Int16ul),
    "str" / If(lambda ctx: ctx.file_type & 4 == 0, Bstr)
)

SRP0 = Struct(
    "unk1" / Int16ul,
    "unk2" / Int16ul,
    "should_be_3" / Int16ul,
    "count" / Int16ul,
    "entries" / Array(lambda ctx: ctx.count, SRP_ENTRY),
    "count2" / Int16ul,
    "strings" / Array(lambda ctx: ctx.count2, Bstr),
    "srp" / create_srp(SRPInfo(type=SRPModuleType.PROJECT, args={}))
)


def parse_hlnam(raw_hlnam: int) -> int:
    if (raw_hlnam & 0xFFFE) == 65534:
        return 0xFFFF
    return ((raw_hlnam & 0xFFFE) - 2) >> 1


class DefnType(enum.Enum):
    FUNC = enum.auto()
    VAR = enum.auto()
    REC_TYPE = enum.auto()
    PARAM = enum.auto()


def get_defn_type(flag1: int) -> DefnType:
    match (flag1 & 7):
        case 4 | 3:
            return DefnType.FUNC
        case 2 | 0:
            return DefnType.VAR
        case 1:
            return DefnType.PARAM
        case 6:
            return DefnType.REC_TYPE


def is_defn_member(flag1: int):
    return (flag1 & 7) in (2, 3, 4)


def get_cargs(flag1: int, flag2: int) -> int:
    result = flag2 & 0x3f
    if flag1 & 0x20:
        result -= 1
    if flag1 & 0x40:
        result -= 1
    return result


def get_cargs_opt(flag3: int) -> int:
    opt = (flag3 & 0x3f)
    if opt == 63:
        return -1
    return opt


def is_sub(result_offset: int, flag1: int) -> bool:
    if (flag1 & 8) == 0:
        return result_offset == -1
    return (result_offset & 0x3f) == 24 and (result_offset & 0x700) == 0


def get_indirection(flag1: int, flag2: int, flag3: int, inner_flag1: int):
    if flag2 & 0x10 or flag2 & 0x40 or flag1 & 0x8 or flag3 & 0x4:
        return 0
    return ((inner_flag1 & 0xfff) + 1) + 0xfff


DEFN_CHILDREN_ARRAY = Array(0x10, Int32sl)

DEFN = Struct(
    "start" / Tell,
    "flag1" / Int8ul,
    "flag2" / Int8ul,
    "raw_hlnam" / Int16ul,
    "next" / Int32sl,
    "hlnam" / Computed(lambda ctx: parse_hlnam(ctx.raw_hlnam)),
    "is_member" / Computed(lambda ctx: is_defn_member(ctx.flag1)),
    "type" / Computed(lambda ctx: get_defn_type(ctx.flag1)),
    "var" / If(lambda ctx: ctx.type in (DefnType.VAR,DefnType.PARAM),
               Struct(
                   "start_var" / Tell,
                   "padding" / Bytes(lambda ctx: 8 - (ctx.start_var - ctx._.start)),
                   "const_val" / Int32sl,
                   "flag1" / Int16ul,
                   "flag2" / Int16ul,
                   "flag3" / Int32sl,
                   "flag4" / Int8ul,
                   "flag5" / Int8ul,
                   "indirection" / Computed(
                       lambda ctx: get_indirection(ctx._.flag1, ctx._.flag2, ctx._.raw_hlnam, ctx.flag1)
                   ),
                   "for_kind" / Computed(
                       lambda ctx: bool((ctx.flag1 >> 12) & 7)
                   ),
                   "has_const_val" / Computed(
                       lambda ctx: bool(ctx._.flag2 & 0x10)
                   ),
                   "is_comp_temp" / Computed(
                       lambda ctx: bool((ctx.flag4 >> 5) & 1)
                   ),
                   "is_ctl_prop" / Computed(
                       lambda ctx: bool(ctx.flag4 & 1)
                   ),
                   "is_data_member" / Computed(
                       lambda ctx: (ctx._.flag2 & 7) == 0
                   ),
                   "is_event_prop" / Computed(
                       lambda ctx: bool((ctx.flag4 >> 2) & 1)
                   ),
                   "is_formal_duplicate" / Computed(
                       lambda ctx: bool(ctx.flag4 >> 7)
                   ),
                   "is_func_retval" / Computed(
                       lambda ctx: bool((ctx.flag4 >> 3) & 1)
                   ),
                   "is_implements" / Computed(
                       lambda ctx: bool((ctx.flag4 >> 4) & 1)
                   ),
                   "is_implicit" / Computed(
                       lambda ctx: (ctx._.flag1 & 0x30) == 0
                   ),
                   "is_local" / Computed(
                       lambda ctx: (ctx._.flag2 & 7) == 4
                   ),
                   "is_private" / Computed(
                       lambda ctx: (ctx._.flag1 & 0x8) == 0
                   ),
                   "is_private_base" / Computed(
                       lambda ctx: bool(ctx.flag5 & 1)
                   ),
                   "is_public" / Computed(
                       lambda ctx: (ctx._.flag1 & 0x8) == 8
                   ),
                   "is_read_only" / Computed(
                       lambda ctx: bool((ctx.flag4 >> 1) & 1)
                   ),
                   "is_static_laid_out" / Computed(
                       lambda ctx: ctx.const_val != -1
                   ),
                   "is_typechar" / Computed(
                       lambda ctx: (ctx._.flag1 & 0x30) == 16
                   ),
                   "is_unembedded_fxstr" / Computed(
                       lambda ctx: False if bool(ctx._.flag1 & 0x40) else bool(ctx.flag3 & 1)
                   ),
                   "is_with_temp" / Computed(
                       lambda ctx: bool((ctx.flag4 >> 6) & 1)
                   )

               )
               ),
    "before_children_offset" / Tell,
    "padding" / Bytes(lambda ctx: (32 if config.IS_32_BIT_VBA6 else 40) - (ctx.before_children_offset - ctx.start)),
    "children_offset" / Int32sl,
    "func" / If(lambda ctx: ctx.type is DefnType.FUNC,
                Struct(
                    "start_func" / Tell,
                    "padding" / Bytes(lambda ctx: (44 if config.IS_32_BIT_VBA6 else 60) - (ctx.start_func - ctx._.start)),
                    "result_offset" / Int32sl,
                    "ovft" / Int16ul,
                    "epi_cookie" / Int16ul,
                    "ulines" / Int16ul,
                    "is_available" / Int16ul,
                    "first_line" / Int16ul,
                    "unk1" / If(not config.IS_32_BIT_VBA6, Int32ul),
                    "flag1" / Int8ul,
                    "flag2" / Int8ul,
                    "flag3" / Int8ul,
                    "flag4" / Int8ul,
                    "cargs" / Computed(lambda ctx: get_cargs(ctx.flag1, ctx.flag2)),
                    "cargs_opt" / Computed(lambda ctx: get_cargs_opt(ctx.flag3)),
                    "CC" / Computed(lambda ctx: ctx.flag1 & 7),
                    "contains_static_var" / Computed(lambda ctx: bool(ctx.flag2 >> 7)),
                    "defines_memid" / Computed(lambda ctx: bool(ctx.flag4 & 1)),
                    "force_return_errors" / Computed(lambda ctx: bool((ctx.flag4 >> 4) & 1)),
                    "return_errors" / Computed(lambda ctx: bool(ctx.flag4 & 8) or bool(ctx.flag4 & 0x10)),
                    "uses_get_last_error" / Computed(lambda ctx: bool((ctx.flag3 >> 6) & 1)),
                    "had_lcid" / Computed(lambda ctx: bool((ctx.flag1 >> 6) & 1)),
                    "had_retval" / Computed(lambda ctx: bool((ctx.flag1 >> 5) & 1)),
                    "is_contained" / Computed(lambda ctx: bool((ctx.flag2 >> 6) & 1)),
                    "is_dispatch" / Computed(lambda ctx: (ctx._.flag1 >> 7) == 3),
                    "is_munged" / Computed(lambda ctx: bool((ctx.flag1 >> 4) & 1)),
                    "is_virtual" / Computed(lambda ctx: (ctx._.flag2 & 7) == 0),
                    "is_owned_by_cache" / Computed(lambda ctx: bool(ctx.flag3 >> 7)),
                    "is_param_array" / Computed(lambda ctx: (ctx.flag3 & 0x3f) == 63),
                    "is_private" / Computed(lambda ctx: (ctx.flag4 & 6) == 0),
                    "is_property_set" / Computed(lambda ctx: bool(ctx._.flag2 >> 7)),
                    "is_ptr_safe" / Computed(lambda ctx: bool((ctx.flag4 >> 5) & 1)),
                    "is_public" / Computed(lambda ctx: (ctx.flag4 & 6) == 2),
                    "is_restricted" / Computed(lambda ctx: bool((ctx._.flag2 >> 3) & 1)),
                    "is_simple_type_result" / Computed(lambda ctx: bool((ctx.flag1 >> 3) & 1)),
                    "is_static" / Computed(lambda ctx: (ctx._.flag2 & 7) == 2),
                    "is_static_local_vars" / Computed(lambda ctx: bool(ctx._.flag1 >> 7)),
                    "is_sub" / Computed(lambda ctx: is_sub(ctx.result_offset, ctx.flag1)),
                    "is_unicode" / Computed(lambda ctx: bool(ctx.flag1 >> 7)),
                )
                )

)
