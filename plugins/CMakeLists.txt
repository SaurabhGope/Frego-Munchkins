foreach(plugin IN LISTS FREGO_PLUGINS)
  add_subdirectory(${plugin})
endforeach()
