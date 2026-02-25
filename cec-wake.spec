Name:           cec-wake
Version:        0.1.0
Release:        1%{?dist}
Summary:        HDMI-CEC wake controller (systemd user service + udev rule)
License:        GPL-3.0-or-later
URL:            https://github.com/jcpunk/%{name}
Source0:        %{url}/archive/refs/tags/%{version}.tar.gz#/%{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  systemd-rpm-macros
Requires:       python3
Requires:       python3-dbus
Requires:       python3-gobject
Requires:       libcec
Requires:       systemd
Requires:       udev

%description
Monitor the desktop screensaver and send HDMI-CEC Active Source
commands to wake attached TVs when the screen is unlocked.

This package installs:
 - /usr/libexec/cec_wake_daemon
 - /usr/lib/systemd/user/cec-wake.service
 - /usr/lib/udev/rules.d/99-cec.rules

%prep
%autosetup

%build
# no build step; script-only package
true

%install
# install and rename the script to remove the .py suffix
install -D -m 0755 cec_wake_daemon.py %{buildroot}/%{_libexecdir}/cec_wake_daemon
install -D -m 0644 cec-wake.service %{buildroot}/%{_userunitdir}/cec-wake.service
install -D -m 0644 99-cec.rules %{buildroot}/%{_udevrulesdir}/99-cec.rules

%files
%license LICENSE
%doc README.md
%doc dri-card0.rules
%doc cec-wake.conf
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
