# Applied globally so third-party code is instrumented too (mixing sanitized and
# unsanitized code gives false negatives).
if(FREGO_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()
