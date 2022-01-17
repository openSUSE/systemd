foreach prog : ['path_id_compat.c']

        executable(prog.split('.')[0],
                   prog,
                   include_directories : includes,
                   c_args : ['-DLOG_REALM=LOG_REALM_UDEV'],
                   link_with : [libudev_internal],
                   install_rpath : udev_rpath,
                   install : true,
                   install_dir : udevlibexecdir)
endforeach
