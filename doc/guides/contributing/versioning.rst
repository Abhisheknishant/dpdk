..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018 The DPDK contributors

DPDK ABI/API policy
===================

Description
-----------

This document details some methods for handling ABI management in the DPDK.

General Guidelines
------------------

#. Major ABI versions are declared every **two years** and are then supported
   for two years, typically aligned with the LTS release.
#. ABI versioning is managed at a project level in DPDK, with the supported ABI
   version reflected in all library's soname.
#. The ABI should be preserved and not changed lightly. The ABI may be changed
   following the outlined deprecation process.
#. The addition of symbols is generally not problematic. The modification of
   symbols should be managed with ABI versioning.
#. The removal of symbols is considered an ABI breakage, once approved these
   will form part of the next ABI version.
#. Libraries or APIs marked as ``experimental`` are not considered part of the
   major ABI version and may change without constraint.
#. Updates to the minimum hardware requirements, which drop support for hardware
   which was previously supported, should be treated as an ABI change.

What is an ABI?
~~~~~~~~~~~~~~~

An ABI (Application Binary Interface) is the set of runtime interfaces exposed
by a library. It is similar to an API (Application Programming Interface) but
is the result of compilation.  It is also effectively cloned when applications
link to dynamic libraries.  That is to say when an application is compiled to
link against dynamic libraries, it is assumed that the ABI remains constant
between the time the application is compiled/linked, and the time that it runs.
Therefore, in the case of dynamic linking, it is critical that an ABI is
preserved, or (when modified), done in such a way that the application is unable
to behave improperly or in an unexpected fashion.

What is a library's soname?
~~~~~~~~~~~~~~~~~~~~~~~~~~~

System libraries usually adopt the familiar major and minor version naming
convention, where major versions (e.g. ``librte_a 1.x, 2.x``) are presumed to be
ABI incompatible with each other and minor versions (e.g. ``librte_a 2.11,
2.12``) are presumed to be ABI compatible. A library's `soname
<https://en.wikipedia.org/wiki/Soname>`_. is typically used to provide backward
compatibility information about a given library, describing the lowest common
denominator ABI supported by the library. The soname is typically comprised of
the library's name and major version e.g. ``librte_a.so.20``.

During an application's build process, a library's soname is noted as a runtime
dependency of the application. This information is then used by the `dynamic
linker <https://en.wikipedia.org/wiki/Dynamic_linker>`_ when resolving the
applications dependencies at runtime, to load a library supporting the correct
ABI version. The library loaded at runtime therefore, may be a minor revision
supporting the same major abi version (e.g. ``librte_a 20.12``), as the library
used to link the application (e.g ``librte_a 20.0``).

The DPDK ABI policy
-------------------

A major ABI version is declared every two years, aligned with that years LTS
release, e.g. v19.11 . This ABI version is then supported for two years by all
subsequent releases within that time period, typically including the next LTS
release, e.g. v20.11.

At the declaration of a major ABI version, major version numbers encoded in
libraries soname's are bumped to indicate the new version, with minor version
reset to 0. An example would be ``librte_a.so.20.5`` would become
``librte_a.so.21.0``

The ABI may change then multiple times, without warning, between the last major
ABI version increment and the HEAD label of the git tree, with the condition
that ABI compatibility with the major ABI version is preserved and therefore
soname's do not change.

ABI versions, are supported by each release until such time as the next major
ABI version is declared. At that time, the deprecation of the previous major ABI
version will be noted in the Release Notes with guidance on individual symbol
depreciation and upgrade notes provided.

ABI Changes
~~~~~~~~~~~

The ABI may still change after the declaration of a major ABI version, that is
new APIs may be still added or existing APIs may be modified. The requirements
for doing so are:

#. At least 3 acknowledgments of the need to do so must be made on the
   dpdk.org mailing list.

   - The acknowledgment of the maintainer of the component is mandatory, or if
     no maintainer is available for the component, the tree/sub-tree maintainer
     for that component must acknowledge the ABI change instead.

   - The acknowledgment of a member of the technical board, as a delegate of the
     `technical board <https://core.dpdk.org/techboard/>`_ acknowledging the
     need for the ABI change, is also mandatory.

   - It is also recommended that acknowledgments from different "areas of
     interest" be sought for each deprecation, for example: from NIC vendors,
     CPU vendors, end-users, etc.

#. Backward compatibly with the major ABI version must be maintained through
   `ABI versioning`_, with forward-only compatibility offered for any ABI
   changes that are indicated to be part of the next ABI version.

   - In situations where backward compatibility is not possible, read the
     section `ABI  Breakages`_.

   - No backward or forward compatibility is offered for API changes marked as
     ``experimental``, as described in the section `Experimental APIs`_.

#. If a newly proposed API functionally replaces an existing one, when the new
   API becomes non-experimental then the old one is marked with
   ``__rte_deprecated``.

    - The depreciated API should follow the notification process to be removed,
      see `Examples of Deprecation Notices`_;

    - At the declaration of the next major ABI version, those ABI changes then
      become a formal part of the new ABI and the requirement to preserve ABI
      compatibility with the last major ABI version is then dropped.

.. note::

   Note that the above process for ABI deprecation should not be undertaken
   lightly. ABI stability is extremely important for downstream consumers of the
   DPDK, especially when distributed in shared object form. Every effort should
   be made to preserve the ABI whenever possible. The ABI should only be changed
   for significant reasons, such as performance enhancements. ABI breakage due
   to changes such as reorganizing public structure fields for aesthetic or
   readability purposes should be avoided.

.. note::

   Note that forward-only compatibility is offered for those changes made
   between major ABI versions. The soname however only describes compatibility
   with the last major ABI version and until the next major ABI version is
   declared, these changes therefore cannot be resolved as a runtime dependency
   through the soname. Therefore any application wishing to make use of these
   ABI changes can only ensure that it's runtime dependencies are met through
   Operating System package versioning.

.. note::

   Updates to the minimum hardware requirements, which drop support for hardware
   which was previously supported, should be treated as an ABI change, and
   follow the relevant deprecation policy procedures as above: 3 acks, technical
   board approval and announcement at least one release in advance.


ABI Breakages
^^^^^^^^^^^^^

For those ABI changes that may be too significant to reasonably maintain
multiple versions. In those cases, ABIs may be updated without backward
compatibility being provided.

The additional requirements to approve an ABI breakage, on top of those
described in the section `ABI Changes`_ are:

#. ABI breaking changes (including an alternative map file) can be included with
   deprecation notice, in wrapped way by the ``RTE_NEXT_ABI`` option, to provide
   more details about oncoming changes. ``RTE_NEXT_ABI`` wrapper will be removed
   at the declaration of the next major ABI version.

#. Once approved and after the depreciation notice has been observed these
   changes will form part of the next declared major ABI version.

Examples of ABI Changes
^^^^^^^^^^^^^^^^^^^^^^^

The following are examples of allowable ABI changes occurring between
declarations of major ABI versions.

* DPDK 20.0 release defines the function ``rte_foo()``, and ``rte_foo()``
  is part of the major ABI version DPDK 20.0.

* DPDK 20.2 release defines a new function ``rte_foo(uint8_t bar)``, and
  this is not a problem as long as the symbol ``rte_foo@DPDK20.0`` is
  preserved through `ABI versioning`_.

  - The new function may be marked with the ``__rte_experimental`` tag for a
    number of releases, as described in the section `Experimental APIs`_;

  - Once ``rte_foo(uint8_t bar)`` becomes non-experimental ``rte_foo()`` is then
    declared as ``__rte_depreciated``, with an associated deprecation notice
    provided.

* DPDK 20.1 is not re-released to include ``rte_foo(uint8_t bar)``, the new
  version of ``rte_foo`` only exists from DPDK 20.2 onwards (forward-only
  compatibility).

* DPDK 20.1 release defines the experimental function ``__rte_experimental
  rte_baz()``. This function may or may not exist in DPDK 20.2 and DPDK 21.0
  releases.

* An application ``dPacket`` wishes to use ``rte_foo(uint8_t bar)``, before the
  declaration of the DPDK 21.0 major API version. The application can only
  ensure it's runtime dependencies are met by specifying ``DPDK (>= 20.2)`` as
  an explicit package dependency, as the soname only may only indicate the
  supporting major ABI version.

* At DPDK 21.0 release the function ``rte_foo(uint8_t bar)`` becomes
  formally part of the major ABI version DPDK 21.0 and ``rte_foo()`` may be
  removed.


Examples of Deprecation Notices
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following are some examples of ABI deprecation notices which would be
added to the Release Notes:

* The Macro ``#RTE_FOO`` is deprecated and will be removed with version 21.0,
  to be replaced with the inline function ``rte_foo()``.

* The function ``rte_mbuf_grok()`` has been updated to include a new parameter
  in version 20.2. Backwards compatibility will be maintained for this function
  until the release of DPDK version 21.0

* The members of ``struct rte_foo`` have been reorganized in release 20.1 for
  performance reasons. Existing binary applications will have backwards
  compatibility in release 20.1, while newly built binaries will need to
  reference the new structure variant ``struct rte_foo2``. Compatibility will
  be removed in release 21.0, and all applications will require updating and
  rebuilding to the new structure at that time, which will be renamed to the
  original ``struct rte_foo``.

* Significant ABI changes are planned for the ``librte_dostuff`` library. The
  upcoming release 20.1 will not contain these changes, but release 21.0 will,
  and no backwards compatibility is planned due to the extensive nature of
  these changes. Binaries using this library built prior to version 21.0 will
  require updating and recompilation.

Experimental APIs
-----------------

APIs marked as ``experimental`` are not considered part of an ABI version and
may change without warning at any time. Since changes to APIs are most likely
immediately after their introduction, as users begin to take advantage of those
new APIs and start finding issues with them, new DPDK APIs will be automatically
marked as ``experimental`` to allow for a period of stabilization before they
become part of a tracked ABI version.

Note that marking an API as experimental is a multi step process.
To mark an API as experimental, the symbols which are desired to be exported
must be placed in an EXPERIMENTAL version block in the corresponding libraries'
version map script.
Secondly, the corresponding prototypes of those exported functions (in the
development header files), must be marked with the ``__rte_experimental`` tag
(see ``rte_compat.h``).
The DPDK build makefiles perform a check to ensure that the map file and the
C code reflect the same list of symbols.
This check can be circumvented by defining ``ALLOW_EXPERIMENTAL_API``
during compilation in the corresponding library Makefile.

In addition to tagging the code with ``__rte_experimental``,
the doxygen markup must also contain the EXPERIMENTAL string,
and the MAINTAINERS file should note the EXPERIMENTAL libraries.

For removing the experimental tag associated with an API, deprecation notice
is not required. Though, an API should remain in experimental state for at least
one release. Thereafter, normal process of posting patch for review to mailing
list can be followed.


ABI Versioning
--------------

Major ABI versions
~~~~~~~~~~~~~~~~~~

An ABI version change to a given library, especially in core libraries such as
``librte_mbuf``, may cause an implicit ripple effect on the ABI of it's
dependent libraries, causing ABI breakages. There may however be no explicit
reason to bump a dependent libraries ABI version, as there may have been no
obvious change to the dependent library's API, even though the library's ABI
compatibility will have been broken.

This interdependence of libraries, means that ABI versioning of libraries is
more manageable at a project level, with all project libraries sharing a
**single ABI version**. In addition, the need to maintain a stable ABI for some
number of releases as described in the section `The DPDK ABI policy`_, means
that ABI version increments need to carefully planned and managed at a project
level.

Major ABI versions are therefore declared every two years and are then supported
for two years, typically aligned with the LTS release and are shared across all
libraries. This means that a single project level ABI version, reflected in all
individual library's soname, filename and version maps persists for two years.

.. code-block:: none

 $ head ./lib/librte_acl/rte_acl_version.map
 DPDK_20.0 {
        global:
 ...

 $ head ./lib/librte_eal/rte_eal_version.map
 DPDK_20.0 {
        global:
 ...

When an ABI change is made between major ABI versions to a given library, a new
section is added to that library's version map describing the impending new ABI
version, as described in the section `Examples of ABI Macro use`_. The
libraries soname and filename however do not change, e.g. ``libacl.so.20``, as
ABI compatibility with the last major ABI version continues to be preserved for
that library.

.. code-block:: none

 $ head ./lib/librte_acl/rte_acl_version.map
 DPDK_20.0 {
        global:
 ...

 DPDK_21.0 {
        global:

 } DPDK_20.0;
 ...

 $ head ./lib/librte_eal/rte_eal_version.map
 DPDK_20.0 {
        global:
 ...


However when a new ABI version is declared, for example DPDK 21.0, old
depreciated functions may be safely removed at this point and the entire old
major ABI version removed, see section `Deprecating an entire ABI version`_ on
how this may be done.

.. code-block:: none

 $ head ./lib/librte_acl/rte_acl_version.map
 DPDK_21.0 {
        global:
 ...

 $ head -n 3 ./lib/librte_eal/rte_eal_version.map
 DPDK_21.0 {
        global:
 ...

At the same time, the major ABI version is changed atomically across all
libraries by incrementing the major version in individual library's soname, e.g.
``libacl.so.21``. This is done by bumping the LIBABIVER number in the libraries
Makefile to indicate to dynamic linking applications that this is a later, and
possibly incompatible library version:

.. code-block:: c

   -LIBABIVER := 20
   +LIBABIVER := 21


Versioning Macros
~~~~~~~~~~~~~~~~~

When a symbol is exported from a library to provide an API, it also provides a
calling convention (ABI) that is embodied in its name, return type and
arguments. Occasionally that function may need to change to accommodate new
functionality or behavior. When that occurs, it is may be required to allow for
backward compatibility for a time with older binaries that are dynamically
linked to the DPDK.

To support backward compatibility the ``rte_compat.h``
header file provides macros to use when updating exported functions. These
macros are used in conjunction with the ``rte_<library>_version.map`` file for
a given library to allow multiple versions of a symbol to exist in a shared
library so that older binaries need not be immediately recompiled.

The macros exported are:

* ``VERSION_SYMBOL(b, e, n)``: Creates a symbol version table entry binding
  versioned symbol ``b@DPDK_n`` to the internal function ``b_e``.

* ``BIND_DEFAULT_SYMBOL(b, e, n)``: Creates a symbol version entry instructing
  the linker to bind references to symbol ``b`` to the internal symbol
  ``b_e``.

* ``MAP_STATIC_SYMBOL(f, p)``: Declare the prototype ``f``, and map it to the
  fully qualified function ``p``, so that if a symbol becomes versioned, it
  can still be mapped back to the public symbol name.

Examples of ABI Macro use
^^^^^^^^^^^^^^^^^^^^^^^^^

Updating a public API
_____________________

Assume we have a function as follows

.. code-block:: c

 /*
  * Create an acl context object for apps to
  * manipulate
  */
 struct rte_acl_ctx *
 rte_acl_create(const struct rte_acl_param *param)
 {
        ...
 }


Assume that struct rte_acl_ctx is a private structure, and that a developer
wishes to enhance the acl api so that a debugging flag can be enabled on a
per-context basis.  This requires an addition to the structure (which, being
private, is safe), but it also requires modifying the code as follows

.. code-block:: c

 /*
  * Create an acl context object for apps to
  * manipulate
  */
 struct rte_acl_ctx *
 rte_acl_create(const struct rte_acl_param *param, int debug)
 {
        ...
 }


Note also that, being a public function, the header file prototype must also be
changed, as must all the call sites, to reflect the new ABI footprint.  We will
maintain previous ABI versions that are accessible only to previously compiled
binaries

The addition of a parameter to the function is ABI breaking as the function is
public, and existing application may use it in its current form. However, the
compatibility macros in DPDK allow a developer to use symbol versioning so that
multiple functions can be mapped to the same public symbol based on when an
application was linked to it. To see how this is done, we start with the
requisite libraries version map file. Initially the version map file for the acl
library looks like this

.. code-block:: none

   DPDK_20.0 {
        global:

        rte_acl_add_rules;
        rte_acl_build;
        rte_acl_classify;
        rte_acl_classify_alg;
        rte_acl_classify_scalar;
        rte_acl_create;
        rte_acl_dump;
        rte_acl_find_existing;
        rte_acl_free;
        rte_acl_ipv4vlan_add_rules;
        rte_acl_ipv4vlan_build;
        rte_acl_list_dump;
        rte_acl_reset;
        rte_acl_reset_rules;
        rte_acl_set_ctx_classify;

        local: *;
   };

This file needs to be modified as follows

.. code-block:: none

   DPDK_20.0 {
        global:

        rte_acl_add_rules;
        rte_acl_build;
        rte_acl_classify;
        rte_acl_classify_alg;
        rte_acl_classify_scalar;
        rte_acl_create;
        rte_acl_dump;
        rte_acl_find_existing;
        rte_acl_free;
        rte_acl_ipv4vlan_add_rules;
        rte_acl_ipv4vlan_build;
        rte_acl_list_dump;
        rte_acl_reset;
        rte_acl_reset_rules;
        rte_acl_set_ctx_classify;

        local: *;
   };

   DPDK_21.0 {
        global:
        rte_acl_create;

   } DPDK_20.0;

The addition of the new block tells the linker that a new version node is
available (DPDK_21.0), which contains the symbol rte_acl_create, and inherits
the symbols from the DPDK_20.0 node. This list is directly translated into a
list of exported symbols when DPDK is compiled as a shared library

Next, we need to specify in the code which function map to the rte_acl_create
symbol at which versions.  First, at the site of the initial symbol definition,
we need to update the function so that it is uniquely named, and not in conflict
with the public symbol name

.. code-block:: c

  struct rte_acl_ctx *
 -rte_acl_create(const struct rte_acl_param *param)
 +rte_acl_create_v20(const struct rte_acl_param *param)
 {
        size_t sz;
        struct rte_acl_ctx *ctx;
        ...

Note that the base name of the symbol was kept intact, as this is conducive to
the macros used for versioning symbols.  That is our next step, mapping this new
symbol name to the initial symbol name at version node 20.0.  Immediately after
the function, we add this line of code

.. code-block:: c

   VERSION_SYMBOL(rte_acl_create, _v20, 20.0);

Remembering to also add the rte_compat.h header to the requisite c file where
these changes are being made. The above macro instructs the linker to create a
new symbol ``rte_acl_create@DPDK_20.0``, which matches the symbol created in
older builds, but now points to the above newly named function. We have now
mapped the original rte_acl_create symbol to the original function (but with a
new name)

Next, we need to create the 21.0 version of the symbol. We create a new function
name, with a different suffix, and implement it appropriately

.. code-block:: c

   struct rte_acl_ctx *
   rte_acl_create_v21(const struct rte_acl_param *param, int debug);
   {
        struct rte_acl_ctx *ctx = rte_acl_create_v20(param);

        ctx->debug = debug;

        return ctx;
   }

This code serves as our new API call. Its the same as our old call, but adds the
new parameter in place. Next we need to map this function to the symbol
``rte_acl_create@DPDK_21.0``. To do this, we modify the public prototype of the
call in the header file, adding the macro there to inform all including
applications, that on re-link, the default rte_acl_create symbol should point to
this function. Note that we could do this by simply naming the function above
rte_acl_create, and the linker would chose the most recent version tag to apply
in the version script, but we can also do this in the header file

.. code-block:: c

   struct rte_acl_ctx *
   -rte_acl_create(const struct rte_acl_param *param);
   +rte_acl_create_v21(const struct rte_acl_param *param, int debug);
   +BIND_DEFAULT_SYMBOL(rte_acl_create, _v21, 21.0);

The BIND_DEFAULT_SYMBOL macro explicitly tells applications that include this
header, to link to the rte_acl_create_v21 function and apply the DPDK_21.0
version node to it.  This method is more explicit and flexible than just
re-implementing the exact symbol name, and allows for other features (such as
linking to the old symbol version by default, when the new ABI is to be opt-in
for a period.

One last thing we need to do.  Note that we've taken what was a public symbol,
and duplicated it into two uniquely and differently named symbols.  We've then
mapped each of those back to the public symbol ``rte_acl_create`` with different
version tags.  This only applies to dynamic linking, as static linking has no
notion of versioning.  That leaves this code in a position of no longer having a
symbol simply named ``rte_acl_create`` and a static build will fail on that
missing symbol.

To correct this, we can simply map a function of our choosing back to the public
symbol in the static build with the ``MAP_STATIC_SYMBOL`` macro.  Generally the
assumption is that the most recent version of the symbol is the one you want to
map.  So, back in the C file where, immediately after ``rte_acl_create_v21`` is
defined, we add this


.. code-block:: c

   struct rte_acl_ctx *
   rte_acl_create_v21(const struct rte_acl_param *param, int debug)
   {
        ...
   }
   MAP_STATIC_SYMBOL(struct rte_acl_ctx *rte_acl_create(const struct rte_acl_param *param, int debug), rte_acl_create_v21);

That tells the compiler that, when building a static library, any calls to the
symbol ``rte_acl_create`` should be linked to ``rte_acl_create_v21``

That's it, on the next shared library rebuild, there will be two versions of
rte_acl_create, an old DPDK_20.0 version, used by previously built applications,
and a new DPDK_21.0 version, used by future built applications.


Deprecating part of a public API
________________________________

Lets assume that you've done the above update, and in preparation for the next
major ABI version you decide you would like to retire the old version of the
function. After having gone through the ABI deprecation announcement process,
removal is easy. Start by removing the symbol from the requisite version map
file:

.. code-block:: none

   DPDK_20.0 {
        global:

        rte_acl_add_rules;
        rte_acl_build;
        rte_acl_classify;
        rte_acl_classify_alg;
        rte_acl_classify_scalar;
        rte_acl_dump;
 -      rte_acl_create
        rte_acl_find_existing;
        rte_acl_free;
        rte_acl_ipv4vlan_add_rules;
        rte_acl_ipv4vlan_build;
        rte_acl_list_dump;
        rte_acl_reset;
        rte_acl_reset_rules;
        rte_acl_set_ctx_classify;

        local: *;
   };

   DPDK_21.0 {
        global:
        rte_acl_create;
   } DPDK_20.0;


Next remove the corresponding versioned export.

.. code-block:: c

 -VERSION_SYMBOL(rte_acl_create, _v20, 2.0);


Note that the internal function definition could also be removed, but its used
in our example by the newer version _v21, so we leave it in place and declare it
as static. This is a coding style choice.

Deprecating an entire ABI version
_________________________________

While removing a symbol from an ABI may be useful, it is more practical to
remove an entire version node at once, as is typically done at the declaration
of a major ABI version. If a version node completely specifies an API, then
removing part of it, typically makes it incomplete. In those cases it is better
to remove the entire node.

To do this, start by modifying the version map file, such that all symbols from
the node to be removed are merged into the next node in the map.

In the case of our map above, it would transform to look as follows

.. code-block:: none

   DPDK_21.0 {
        global:

        rte_acl_add_rules;
        rte_acl_build;
        rte_acl_classify;
        rte_acl_classify_alg;
        rte_acl_classify_scalar;
        rte_acl_dump;
        rte_acl_create
        rte_acl_find_existing;
        rte_acl_free;
        rte_acl_ipv4vlan_add_rules;
        rte_acl_ipv4vlan_build;
        rte_acl_list_dump;
        rte_acl_reset;
        rte_acl_reset_rules;
        rte_acl_set_ctx_classify;

        local: *;
 };

Then any uses of BIND_DEFAULT_SYMBOL that pointed to the old node should be
updated to point to the new version node in any header files for all affected
symbols.

.. code-block:: c

 -BIND_DEFAULT_SYMBOL(rte_acl_create, _v20, 20.0);
 +BIND_DEFAULT_SYMBOL(rte_acl_create, _v21, 21.0);

Lastly, any VERSION_SYMBOL macros that point to the old version node should be
removed, taking care to keep, where need old code in place to support newer
versions of the symbol.


Running the ABI Validator
-------------------------

The ``devtools`` directory in the DPDK source tree contains a utility program,
``validate-abi.sh``, for validating the DPDK ABI based on the Linux `ABI
Compliance Checker
<http://ispras.linuxbase.org/index.php/ABI_compliance_checker>`_.

This has a dependency on the ``abi-compliance-checker`` and ``and abi-dumper``
utilities which can be installed via a package manager. For example::

   sudo yum install abi-compliance-checker
   sudo yum install abi-dumper

The syntax of the ``validate-abi.sh`` utility is::

   ./devtools/validate-abi.sh <REV1> <REV2>

Where ``REV1`` and ``REV2`` are valid gitrevisions(7)
https://www.kernel.org/pub/software/scm/git/docs/gitrevisions.html
on the local repo.

For example::

   # Check between the previous and latest commit:
   ./devtools/validate-abi.sh HEAD~1 HEAD

   # Check on a specific compilation target:
   ./devtools/validate-abi.sh -t x86_64-native-linux-gcc HEAD~1 HEAD

   # Check between two tags:
   ./devtools/validate-abi.sh v2.0.0 v2.1.0

   # Check between git master and local topic-branch "vhost-hacking":
   ./devtools/validate-abi.sh master vhost-hacking

After the validation script completes (it can take a while since it need to
compile both tags) it will create compatibility reports in the
``./abi-check/compat_report`` directory. Listed incompatibilities can be found
as follows::

  grep -lr Incompatible abi-check/compat_reports/
