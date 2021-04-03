include $(RIOTBASE)/Makefile.base

# FIXME: These are the defaults; I guess we'll need to pass down everything, and not just CARGO_TARGET
include ../../makefiles/cargo-settings.inc.mk

# The single Rust library to be built collection modules
# Not placing this in $(BINDIR)/rust_lib_catchall/target/... as that'd mean
# that the find in _LINK can catch on to some .o files not intended to be found
CARGO_LIB_MODULES = $(BINDIR)/rust_lib_catchall-target/$(CARGO_TARGET)/${CARGO_PROFILE}/librust_lib_catchall.a

# FIXME: This is the point where any RIOT modules written in Rust (which would
# be pseudomodules depending on this) are turned into a list of features to be
# enabled
CARGO_OPTIONS += --features riot-shell-commands

$(CARGO_LIB_MODULES): $(RIOTBUILD_CONFIG_HEADER_C) $(BUILDDEPS) FORCE
	$(Q)[ x"${CARGO_TARGET}" != x"" ] || (echo "Error: No CARGO_TARGET was set for this platform"; exit 1)
	# differenct to standalone: this uses only CFLAGS and not
	# CFLAGS_WITGH_MACROS, and then hacks the modules back from the
	# exported USEMODULE variable (which may generally be a good idea until
	# compile-commands are available)
	$(Q)CC= CFLAGS= CPPFLAGS= CXXFLAGS= RIOT_CC="${CC}" RIOT_CFLAGS="$(CFLAGS) $(patsubst %,-DMODULE_%,$(USEMODULE)) $(INCLUDES) $(CARGO_EXTRACFLAGS)" cargo +$(CARGO_CHANNEL) build --target $(CARGO_TARGET) `if [ x$(CARGO_PROFILE) = xrelease ]; then echo --release; else if [ x$(CARGO_PROFILE) '!=' xdebug ]; then echo "--profile $(CARGO_PROFILE)"; fi; fi` $(CARGO_OPTIONS) --target-dir $(BINDIR)/rust_lib_catchall-target

rust_lib_catchall.module: $(CARGO_LIB_MODULES) FORCE
	$(Q)# Ensure no old object files persist. These would lead to duplicate
	$(Q)# symbols, or worse, lingering behaivor of XFA entries.
	$(Q)rm -rf $(BINDIR)/rust_lib_catchall/
	$(Q)mkdir -p $(BINDIR)/rust_lib_catchall/
	# difference to standalone: no PWD as it' an absolute path
	$(Q)cd $(BINDIR)/rust_lib_catchall/ && $(AR) x $<

FORCE:

.PHONY: FORCE
