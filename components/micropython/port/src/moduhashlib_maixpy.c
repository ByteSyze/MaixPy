/*
* Copyright 2019 Sipeed Co.,Ltd.

* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <assert.h>
#include <string.h>
#include "py/runtime.h"

#if MICROPY_PY_UHASHLIB_MAIX
#include "sha256.h"
#include "sha1.h"

typedef struct _mp_obj_hash_t {
    mp_obj_base_t base;
    char state[0];
} mp_obj_hash_t;

STATIC const mp_obj_type_t uhashlib_sha256_type;
STATIC const mp_obj_type_t uhashlib_sha1_type;

#if MICROPY_PY_UHASHLIB_SHA256_MAIX
STATIC mp_obj_t uhashlib_sha256_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t uhashlib_sha256_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, char, sizeof(sha256_context_t));
    o->base.type = type;
    sha256_init((sha256_context_t*)o->state, 0xffffffff);//This number can be bigger
    if (n_args == 1) {
        uhashlib_sha256_update(MP_OBJ_FROM_PTR(o), args[0]);
    }
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t uhashlib_sha1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, char, sizeof(SHA1Context));
    o->base.type = type;
    SHA1Reset((SHA1Context*)o->state);
    
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t uhashlib_sha256_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    sha256_update((sha256_context_t*)self->state, bufinfo.buf, bufinfo.len);
    return mp_const_none;
}

STATIC mp_obj_t uhashlib_sha1_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    SHA1Input((SHA1Context*)self->state, bufinfo.buf, bufinfo.len);
    return mp_const_none;
}

STATIC mp_obj_t uhashlib_sha256_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    vstr_t vstr;
    vstr_init_len(&vstr, 32);
    sha256_final((sha256_context_t*)self->state, (byte*)vstr.buf);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC mp_obj_t uhashlib_sha1_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    vstr_t vstr;
    vstr_init_len(&vstr, 20);
    SHA1Result((SHA1Context*)self->state, (byte*)vstr.buf);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC mp_obj_t uhashlib_sha256_hard(mp_obj_t self_in,mp_obj_t arg) {
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    vstr_t vstr;
    vstr_init_len(&vstr, 32);
    sha256_hard_calculate(bufinfo.buf, bufinfo.len, (byte*)vstr.buf);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC mp_obj_t uhashlib_sha1_copy(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_obj_hash_t *copy = m_new_obj_var(mp_obj_hash_t, char, sizeof(SHA1Context));

    SHA1Context *ctx_copy = ((SHA1Context*)copy->state);
    SHA1Context *ctx_orig = ((SHA1Context*)self->state);

    int i = 0;

    copy->base.type = self->base.type;

    for(i = 0; i < SHA1HashSize/4; i++)
	    ctx_copy->Intermediate_Hash[i] = ctx_orig->Intermediate_Hash[i];

    ctx_copy->Length_Low = ctx_orig->Length_Low;
    ctx_copy->Length_High = ctx_orig->Length_High;

    ctx_copy->Message_Block_Index = ctx_orig->Message_Block_Index;

    for(i = 0; i < 64; i++)
	    ctx_copy->Message_Block[i] = ctx_orig->Message_Block[i];

    ctx_copy->Computed = ctx_orig->Computed;
    ctx_copy->Corrupted = ctx_orig->Corrupted;

    return MP_OBJ_FROM_PTR(copy);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(uhashlib_sha256_update_obj, uhashlib_sha256_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(uhashlib_sha256_digest_obj, uhashlib_sha256_digest);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(uhashlib_sha256_hard_obj, uhashlib_sha256_hard);

STATIC const mp_rom_map_elem_t uhashlib_sha256_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&uhashlib_sha256_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&uhashlib_sha256_digest_obj) },
    { MP_ROM_QSTR(MP_QSTR_calculate_hard), MP_ROM_PTR(&uhashlib_sha256_hard_obj) },
};
STATIC MP_DEFINE_CONST_DICT(uhashlib_sha256_locals_dict, uhashlib_sha256_locals_dict_table);

STATIC const mp_obj_type_t uhashlib_sha256_type = {
    { &mp_type_type },
    .name = MP_QSTR_sha256,
    .make_new = uhashlib_sha256_make_new,
    .locals_dict = (mp_obj_dict_t*)&uhashlib_sha256_locals_dict,
};

//////////////// SHA1

STATIC MP_DEFINE_CONST_FUN_OBJ_2(uhashlib_sha1_update_obj, uhashlib_sha1_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(uhashlib_sha1_digest_obj, uhashlib_sha1_digest);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(uhashlib_sha1_copy_obj, uhashlib_sha1_copy);

STATIC const mp_rom_map_elem_t uhashlib_sha1_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&uhashlib_sha1_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&uhashlib_sha1_digest_obj) },
    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&uhashlib_sha1_copy_obj) }
};
STATIC MP_DEFINE_CONST_DICT(uhashlib_sha1_locals_dict, uhashlib_sha1_locals_dict_table);

STATIC const mp_obj_type_t uhashlib_sha1_type = {
    { &mp_type_type },
    .name = MP_QSTR_sha1,
    .make_new = uhashlib_sha1_make_new,
    .locals_dict = (mp_obj_dict_t*)&uhashlib_sha1_locals_dict,
};

#endif


STATIC const mp_rom_map_elem_t mp_module_uhashlib_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_uhashlib) },
    { MP_ROM_QSTR(MP_QSTR_sha256), MP_ROM_PTR(&uhashlib_sha256_type) },
    { MP_ROM_QSTR(MP_QSTR_sha1), MP_ROM_PTR(&uhashlib_sha1_type) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_uhashlib_globals, mp_module_uhashlib_globals_table);

const mp_obj_module_t mp_module_uhashlib_maix = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_uhashlib_globals,
};

#endif //MICROPY_PY_UHASHLIB_K210
