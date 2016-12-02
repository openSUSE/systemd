Workflow for patch submission to development git
================================================

1. create a local branch of the latest devel branch
2. add the patch(es)
	- to indicate backports of upstream commits use "git cherry-pick -x" (see Note1 below)
3. do a testbuild and check for errors
4. test the built packages and make sure they fix the bug
5. check wheter the patch needs to be sent upstream
6. send the patch to @systemd-maintainers for review and include in the commit
   message a tag that shows the id of the bug that the patch fixes and the comitter
	- The tag has a special format e.g.: 
	  [fbui: fixes bsc#1234]
 	- A similar format is used when additional information need to be appended to 
          upstream commit messages, for example if a patch needs to be slightly adjusted
          when it was backported:
          [fbui: adjust context]
7. if the patch is ACKed, merge it to the possible devel branches
	- the merge is per default to SUSE/v* unless it's explicitly asked to merge it in a
          specific branch (but needs a good reason to do so).
8. annouce the merge on the systemd-maintainers list

Note1:
------

Added patches are usually backports of upstream commits.
The "-x" switch will automatically append to the backported commit message a
reference to the original commit using a predefined format:

  (cherry picked from commit xxxxx)

Having this line in backported commit message will identify backported
commits from upstream without any ambiguities.


Workflow for creating a new submit from development git to buildservice (Example for SLES12SP2)
===============================================================================================

1. make SP2 git branch is up to date by merging SUSE/v228 in it
2. add relevant patchsets from the systemd-maintainers mailing list
	- save the emails containing the patches and use git-am to add them to the SP2 git branch
3. build locally and do some sanity checking
4. push to the git repo
5. update the corresponding IBS project to fetch the top of the SLE12-SP2 branch 
6. update systemd.changes, enable package publishing and commit
7. test the built packages and make sure they don't break the system 
	- it is recommended to use the systemd testsuite
	- packages are available at: http://download.suse.de/ibs/QA:/SLE12[SP*]/standard/
        - instead of pre-compiled packages, you can also compile the testsuite directly from your 
          sources using the script at: http://beta.suse.com/private/tblume/systemd-testsuite/
8. announce the future release on @systemd-maintainers and include the list of changes
9. wait for some time
10. if no objection then submit the IBS project.


Layout of git branches
======================

For each version of systemd we maintain (currently v210 and v228) we use
a branch to collect all patches that can be applied to all distros based
on the same version of systemd. Namely these branches are SUSE/v210 and
SUSE/v228.

For example, if a fix appears to fix a bug in v210 only and this fix is
needed by all distros based on v210 (namely SLE12, SLE12-SP1, 13.1,
13.2) then this fix will be included in SUSE/v210. Later this branch
will be merged in the branches tracking the changes for distros based on
v210.

However if a fix appears to be needed by all versions of systemd and
should be applied by all distros then the fix is applied to both
SUSE/v210 and SUSE/v228 branches.

We also have a different type of branch: a branch that tracks a old
functionnality that is not present in systemd but we still need to ship
due to backward compat reason. Currently we have 2 branches of that type:

  compats/dev-root-symlink
  compats/persistent-nic-names

Those branches are applied to all distros that still need the
functionality. This is done so the changes for one functionality is kept
in one single place and it's easy from the git repo to see which branch
includes a specific backward feature.

For example:

  $ git branch --merged SLE12-SP2
    SLE12-SP2
    compats/dev-root-symlink
    compats/persistent-nic-names
