module recentPE;

## Notices in this script are rate limited using the sha1 hash of the PE file
@load policy/frameworks/files/hash-all-files

export {
    redef enum Notice::Type += {
        ## Recently_Compiled_PE fires when a PE file has a compile time that
        ## is within the alert_threshold.
        Recently_Compiled_PE
    };

    ## alert_threshold sets the threshold for how new a PE file must be 
    ## before it will generate a NOTICE.
    option alert_threshold = 30days;

    ## policy provides a point for users of this script to whitelist and 
    ## tune this script.
    global recentPE::policy: hook(f: fa_file);
}

event file_state_remove(f: fa_file) &priority=8
    {
    if ( f?$pe )
        {
        # calculate the time delta between now and the compile timestamp on 
        # the observed PE file.
        local td = network_time() - f$pe$ts;

        if ( td < alert_threshold )
            {
            if ( f?$info && f$info?$sha1 && hook recentPE::policy(f) )
                {
                NOTICE([$note=Recently_Compiled_PE, 
                        $f=f, 
                        $identifier=cat(f$info$sha1)]);
                }
            }
        }
    }