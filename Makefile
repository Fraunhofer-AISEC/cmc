# Builds and installs the CMC binaries, default configs and systemd units.
#
# Run the install targets as root for a system-wide install, or as a regular
# user for an install into the home directory. Components:
#   device: cmcd, cmcctl (attested machines)
#   infra:  estserver, cmcbackend (provisioning and monitoring servers)
#   tools:  operator tools for metadata and reference value generation
#   caddy:  caddy-atls, Caddy with the aTLS plugin (attested reverse proxy)

DEVICE := cmcd cmcctl
INFRA  := estserver cmcbackend
TOOLS  := metatool mrtool snptool tdxtool azuretool
CADDY  := caddy-atls

DEVICE_UNITS := cmcd
INFRA_UNITS  := estserver cmcbackend
CADDY_UNITS  := caddy-atls

BUILDDIR ?= build
# Build tags, e.g. TAGS=nodefaults,socket,tpm for a reduced build
TAGS ?=

ifeq ($(shell id -u),0)
MODE      := system
PREFIX    ?= /usr/local
CONFDIR   := /etc/cmc
DATADIR   := /var/lib/cmc
RUNDIR    := /run/cmc
UNITDIR   ?= $(PREFIX)/lib/systemd/system
WANTEDBY  := multi-user.target
SYSTEMCTL := systemctl
# Sandboxing is only applied to system units, as it implies PrivateUsers= for
# user units, which breaks group-based device access, e.g. to /dev/tpmrm0
UNIT_SED  :=
else
MODE      := user
XDG_CONF  := $(or $(XDG_CONFIG_HOME),$(HOME)/.config)
PREFIX    ?= $(HOME)/.local
CONFDIR   := $(XDG_CONF)/cmc
DATADIR   := $(or $(XDG_DATA_HOME),$(HOME)/.local/share)/cmc
RUNDIR    := $(if $(XDG_RUNTIME_DIR),$(XDG_RUNTIME_DIR)/cmc,$(DATADIR)/run)
UNITDIR   ?= $(XDG_CONF)/systemd/user
WANTEDBY  := default.target
SYSTEMCTL := systemctl --user
UNIT_SED  := -e '/^Protect/d'
endif
BINDIR ?= $(PREFIX)/bin

pkg = $(if $(filter $(1),$(DEVICE)),./$(1),./tools/$(1))

.DEFAULT_GOAL := build
.PHONY: build build-infra build-tools build-caddy build-all egocmc clean FORCE \
	install install-infra install-tools install-caddy install-all \
	uninstall uninstall-infra uninstall-tools uninstall-caddy uninstall-all \
	mode-notice reload

build: $(addprefix $(BUILDDIR)/,$(DEVICE))
build-infra: $(addprefix $(BUILDDIR)/,$(INFRA))
build-tools: $(addprefix $(BUILDDIR)/,$(TOOLS))
build-caddy: $(BUILDDIR)/$(CADDY)
build-all: build build-infra build-tools build-caddy

# go build decides itself whether anything needs to be rebuilt
$(BUILDDIR)/%: FORCE
	go build -trimpath -ldflags="-s -w" -tags="$(TAGS)" -o $@ $(call pkg,$*)

# Custom Caddy build with the aTLS plugin of this repository
$(BUILDDIR)/$(CADDY): FORCE
	CGO_ENABLED=1 go tool xcaddy build --output $(abspath $@) \
		--with github.com/Fraunhofer-AISEC/cmc/tools/atlscaddy \
		--replace github.com/Fraunhofer-AISEC/cmc=$(CURDIR)

FORCE:

# cmcctl with integrated CMC as SGX enclave, see doc/setup-sgx.md
egocmc:
	cd cmcctl && ego-go build -tags nodefaults,libapi,tpm,snp,tdx,sgx,sw && \
		ego sign ../example-setup/sgx/enclave.json

clean:
	rm -rf $(BUILDDIR)

# The install targets do not build, so that "sudo make install" neither needs
# the go toolchain in the PATH of root nor leaves root-owned build files
define check_built
	@for b in $(1); do \
		[ -x $(BUILDDIR)/$$b ] || { echo "$(BUILDDIR)/$$b not found, run make first"; exit 1; }; \
	done
endef

define install_bins
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(addprefix $(BUILDDIR)/,$(1)) $(DESTDIR)$(BINDIR)
endef

# Writes the default config of each binary, existing configs are kept
define install_configs
	@for b in $(1); do \
		f=$(DESTDIR)$(CONFDIR)/$$b.toml; \
		if [ -e $$f ]; then echo "keeping existing $$f"; \
		else $(BUILDDIR)/$$b config init --output $$f || exit 1; fi; \
	done
endef

SUBST := -e 's|@BINDIR@|$(BINDIR)|g' -e 's|@CONFDIR@|$(CONFDIR)|g' -e 's|@DATADIR@|$(DATADIR)|g' \
	-e 's|@RUNDIR@|$(RUNDIR)|g' -e 's|@WANTEDBY@|$(WANTEDBY)|g'

define install_units
	install -d $(DESTDIR)$(UNITDIR)
	@for u in $(1); do \
		sed $(SUBST) $(UNIT_SED) init/systemd/$$u.service > $(DESTDIR)$(UNITDIR)/$$u.service || exit 1; \
		chmod 0644 $(DESTDIR)$(UNITDIR)/$$u.service; \
		echo "installed $(DESTDIR)$(UNITDIR)/$$u.service"; \
	done
endef

mode-notice:
ifeq ($(MODE),user)
	@echo "Installing for the current user to $(PREFIX), use 'sudo make install' for a system install"
endif

# Reloads systemd unless staging into DESTDIR
reload:
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null; then \
		$(SYSTEMCTL) daemon-reload 2>/dev/null || \
			echo "systemd reload failed, run '$(SYSTEMCTL) daemon-reload'"; \
	fi

install: mode-notice
	$(call check_built,$(DEVICE))
	$(call install_bins,$(DEVICE))
	$(call install_configs,$(DEVICE))
	$(call install_units,$(DEVICE_UNITS))
	@$(MAKE) --no-print-directory reload
	@echo "Adjust $(CONFDIR)/cmcd.toml, then run '$(SYSTEMCTL) enable --now cmcd'"

install-infra: mode-notice
	$(call check_built,$(INFRA))
	$(call install_bins,$(INFRA))
	$(call install_configs,$(INFRA))
	$(call install_units,$(INFRA_UNITS))
	@$(MAKE) --no-print-directory reload

install-tools: mode-notice
	$(call check_built,$(TOOLS))
	$(call install_bins,$(TOOLS))

# Caddy has no config init, so the config is generated from a template
install-caddy: mode-notice
	$(call check_built,$(CADDY))
	$(call install_bins,$(CADDY))
	@f=$(DESTDIR)$(CONFDIR)/caddy-atls.caddyfile; \
	if [ -e $$f ]; then echo "keeping existing $$f"; \
	else install -d $(DESTDIR)$(CONFDIR) && \
		sed $(SUBST) init/caddy/caddy-atls.caddyfile > $$f && chmod 0600 $$f && \
		echo "installed $$f"; fi
	$(call install_units,$(CADDY_UNITS))
	@$(MAKE) --no-print-directory reload
	@echo "Adjust $(CONFDIR)/caddy-atls.caddyfile, then run '$(SYSTEMCTL) enable --now caddy-atls'"

install-all: install install-infra install-tools install-caddy

# Configs and data are kept
uninstall:
	rm -f $(addprefix $(DESTDIR)$(BINDIR)/,$(DEVICE))
	rm -f $(patsubst %,$(DESTDIR)$(UNITDIR)/%.service,$(DEVICE_UNITS))
	@$(MAKE) --no-print-directory reload

uninstall-infra:
	rm -f $(addprefix $(DESTDIR)$(BINDIR)/,$(INFRA))
	rm -f $(patsubst %,$(DESTDIR)$(UNITDIR)/%.service,$(INFRA_UNITS))
	@$(MAKE) --no-print-directory reload

uninstall-tools:
	rm -f $(addprefix $(DESTDIR)$(BINDIR)/,$(TOOLS))

uninstall-caddy:
	rm -f $(addprefix $(DESTDIR)$(BINDIR)/,$(CADDY))
	rm -f $(patsubst %,$(DESTDIR)$(UNITDIR)/%.service,$(CADDY_UNITS))
	@$(MAKE) --no-print-directory reload

uninstall-all: uninstall uninstall-infra uninstall-tools uninstall-caddy
