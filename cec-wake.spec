Name:           cec-wake
Version:        0.1.0
Release:        1%{?dist}
Summary:        HDMI-CEC wake controller (systemd user service + udev rule)
License:        GPL-3.0-or-later
URL:            https://github.com/jcpunk/%{name}
Source0:        %{url}/archive/refs/tags/%{version}.tar.gz#/%{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3
BuildRequires:  python3-pytest
BuildRequires:  systemd-rpm-macros
Requires:       python3
# Both are optional at runtime (the daemon degrades gracefully, logging a
# warning, when either is absent) but both are needed for full wake coverage.
Recommends:     python3-dbus
Recommends:     python3-gobject
Recommends:     python3-pywayland
Requires:       libcec
Requires:       systemd
Requires:       udev

%description
Monitor Wayland idle/output-power events and DBus screensaver/logind
signals, and send HDMI-CEC Power-On + Active-Source commands to wake
attached TVs when the display or session comes back.

This package installs:
 - /usr/libexec/cec_wake_daemon (a self-contained Python zipapp; no
   site-packages install step, so it runs unmodified across RHEL/AlmaLinux
   major versions with any Python 3.9+)
 - /usr/lib/systemd/user/cec-wake.service
 - /usr/lib/udev/rules.d/99-cec.rules

%prep
%autosetup

%build
# Package src/cec_wake as a single zipapp executable rather than installing
# it into site-packages.  This keeps the daemon independent of the build
# host's Python minor version and of any particular interpreter's module
# search path, which matters when the same RPM must run unmodified across
# several concurrently supported RHEL/AlmaLinux major versions.
find src/cec_wake -name '__pycache__' -prune -exec rm -rf {} +
%{python3} -m zipapp src -m "cec_wake.cli:main" -p "/usr/bin/python3" \
    -o cec_wake_daemon --compress

%check
# pytest-cov is not available in RHEL/AlmaLinux base repos; run the suite
# without the coverage gate here, since that is a development-loop check
# (see pyproject.toml), not a packaging correctness check.
%{python3} -m pytest -o addopts="" tests

%install
install -D -m 0755 cec_wake_daemon %{buildroot}/%{_libexecdir}/cec_wake_daemon
install -D -m 0644 units/cec-wake.service %{buildroot}/%{_userunitdir}/cec-wake.service
install -D -m 0644 units/99-cec.rules %{buildroot}/%{_udevrulesdir}/99-cec.rules
install -D -m 0644 configs/cec-wake.conf %{buildroot}/%{_pkgdocdir}/cec-wake.conf

%files
%license LICENSE
%doc docs/README.md
%{_pkgdocdir}/cec-wake.conf
%{_libexecdir}/cec_wake_daemon
%{_userunitdir}/cec-wake.service
%{_udevrulesdir}/99-cec.rules

%post
%{?systemd_user_unit_post: %systemd_user_unit_post cec-wake.service}

%preun
%{?systemd_user_unit_preun: %systemd_user_unit_preun cec-wake.service}

%postun
%{?systemd_user_unit_postun: %systemd_user_unit_postun cec-wake.service}

%changelog
