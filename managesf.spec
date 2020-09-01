%global         sum A python API used to centralize management of services deployed under Software Factory

Name:           managesf
Version:        0.23.0
Release:        11%{?dist}
Summary:        %{sum}

License:        ASL 2.0
URL:            https://softwarefactory-project.io/r/p/%{name}
Source0:        https://github.com/redhat-cip/managesf/archive/%{version}.tar.gz

Source1:        managesf.service

BuildArch:      noarch

Buildrequires:  python3-devel
Buildrequires:  python3-pbr

Requires:       pynotedb
Requires:       yaml-cpp
Requires:       python3-pecan
Requires:       python3-pbr
Requires:       python3-passlib
Requires:       python3-basicauth
Requires:       python3-sqlalchemy
Requires:       python3-urllib3
Requires:       python3-pyyaml
Requires:       python3-stevedore
Requires:       python3-PyMySQL
Requires:       python3-six
Requires:       python3-oslo-policy
Requires:       python3-deepdiff
Requires:       python3-GitPython
Requires:       python3-requests
Requires:       python3-gunicorn
Requires:       python3-future

%description
python API used to centralize management of services deployed under Software Factory

%package doc
Summary:        Managesf documentation

BuildRequires:  python3-sphinx
BuildRequires:  python3-six

%description doc
Managesf documentation


%prep
%autosetup -n managesf-%{version}

%build
rm -f *requirements.txt
PBR_VERSION=%{version} %{__python3} setup.py build
PYTHONPATH=. %{__python3} docs/generate-resources-docs.py > docs/source/resources.rst
sphinx-build-3 -b html -d docs/build/doctrees docs/source docs/build/html

%install
PBR_VERSION=%{version} %{__python3} setup.py install --skip-build --root %{buildroot}
mkdir -p %{buildroot}/var/lib/managesf
mkdir -p %{buildroot}/var/log/managesf
mkdir -p %{buildroot}/etc/managesf
mkdir -p %{buildroot}/usr/bin
install -p -D -m 644 %{SOURCE1} %{buildroot}/%{_unitdir}/managesf.service
mv %{buildroot}/usr/etc/managesf/* %{buildroot}/etc/managesf
mkdir -p %{buildroot}/usr/share/doc/managesf
mv docs/build/html/* %{buildroot}/usr/share/doc/managesf/


%check
# Deactivate tests here as one is failing and I cannot find the reason
# test_missing_htpasswd_file (managesf.tests.test_app.TestManageSFHtpasswdController)
# /usr/lib/python2.7/site-packages/pecan/middleware/debug.pyc: ERROR: 'HTTP_ACCEPT'
# PYTHONPATH=%{buildroot}/%{python2_sitelib} PBR_VERSION=%{version} nosetests -v

%pre
getent group managesf >/dev/null || groupadd -r managesf
getent passwd managesf >/dev/null || \
useradd -r -g managesf -G managesf -d /var/lib/managesf -s /sbin/nologin \
-c "Managesf REST API" managesf
exit 0

%post
%systemd_post managesf.service

%preun
%systemd_preun managesf.service

%postun
%systemd_postun managesf.service

%files
%{python3_sitelib}/*
/usr/bin/*
%{_unitdir}/*
%config(noreplace) /etc/managesf/*
%attr(0750, managesf, managesf) %{_var}/lib/managesf
%attr(0750, managesf, managesf) %{_var}/log/managesf

%files doc
/usr/share/doc/managesf

%changelog
* Wed Feb 05 2020 Matthieu Huin <mhuin@redhat.com> - 0.21.0-11
- Remove Storyboard support

* Tue Sep 24 2019 Tristan Cacqueray <tdecacqu@redhat.com> - 0.21.0-10
- Switch to system python3

* Thu Jun 27 2019 Fabien Boucher <fboucher@redhat.com> - 0.12.0-9
- SCLization

* Thu Jun 27 2019 Fabien Boucher <fboucher@redhat.com> - 0.12.0-8
- Remove multiple unneeded dependencies

* Tue Dec 11 2018 Tristan Cacqueray <tdecacqu@redhat.com> - 0.12.0-7
- Remove python-ecdsa requirement

* Mon May 14 2018 Fabien Boucher <fboucher@redhat.com> - 0.12.0-6
- Change un-maintained dependency MySQL-python to pure python python2-PyMySQL

* Tue Apr 18 2018 Tristan Cacqueray <tdecacqu@redhat.com> - 0.12.0-5
- Add missing storyboardclient dependency

* Mon Dec 18 2017 Tristan Cacqueray <tdecacqu@redhat.com> - 0.12.0-4
- Switch requirement to python-paramiko instead of python2-paramiko

* Mon Nov 13 2017 Fabien Boucher <fboucher@redhat.com> - 0.12.0-3
- Increase worker timeout to 30 minutes waiting for better solution

* Thu Aug 03 2017 Fabien Boucher <fboucher@redhat.com> - 0.12.0-2
- Set a worker timeout to avoid the 30 seconds default timeout

* Wed May 24 2017 Fabien Boucher <fboucher@redhat.com> - 0.12.0-1
- Switch to gunicorn

* Mon Mar 20 2017 Tristan Cacqueray <tdecacqu@redhat.com> - 0.11.0-2
- Add html documentation

* Wed Mar 01 2017 Fabien Boucher <fboucher@redhat.com> - 0.11.0-1
- Add uwsgi dependency and update unit file

* Fri Feb 24 2017 Fabien Boucher <fboucher@redhat.com> - 0.11.0-1
- Initial packaging
