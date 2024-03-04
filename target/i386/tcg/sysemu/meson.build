i386_softmmu_ss.add(when: ['CONFIG_TCG', 'CONFIG_SOFTMMU'], if_true: files(
  'tcg-cpu.c',
  'smm_helper.c',
  'excp_helper.c',
  'bpt_helper.c',
  'misc_helper.c',
  'fpu_helper.c',
  'svm_helper.c',
  'seg_helper.c',
))

i386_softmmu_ss.add(when: ['CONFIG_TCG', 'CONFIG_SOFTMMU', 'TARGET_X86_64_ECPT'], if_true: files(
  'ECPT_hash.c',
  'ECPT.c',
))


ecpt_gen = executable('ecpt_gen', 'ecpt_gen_crc64table.c')

gen_table = custom_target('gen_crcr64table',
                        output : ['ecpt_crc64table.h'],
                        command : [ecpt_gen, '@OUTPUT@'])

i386_softmmu_ss.add(gen_table)
