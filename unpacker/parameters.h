#pragma once

static const unsigned int original_image_base_offset = 0x0F;
static const unsigned int rva_of_first_section_offset = 0x14;
static const unsigned int original_image_base_no_fixup_offset = 0x19;
static const unsigned int empty_tls_callback_offset = 0x2;

//YUHZ 2.170906 这几个值都是针对 unpacker专门设计的，作者说是根据执行码，数字节数出来的 :)