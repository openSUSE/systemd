foreach prog : ['path_id_compat.c']

        executable(prog.split('.')[0],
                   prog,
                   include_directories : [includes,
                                          libudev_includes],
                   dependencies : [userspace,
                                   versiondep],
                   c_args : ['-DLOG_REALM=LOG_REALM_UDEV'],
                   link_with : [udev_link_with, libudev_basic],
                   install_rpath : udev_rpath,
                   install : true,
                   install_dir : udevlibexecdir)
endforeach
