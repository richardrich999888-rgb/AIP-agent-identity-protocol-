//! Finding the cgroup v2 hierarchy.
//!
//! On a unified host it is usually `/sys/fs/cgroup`; on a hybrid host (v1
//! controllers plus a v2 hierarchy) it is wherever `cgroup2` is mounted —
//! `/sys/fs/cgroup/unified` on the development host. It is read from the
//! kernel's own mount table, never assumed from a path.

/// The mount point of the first `cgroup2` filesystem in a
/// `/proc/self/mountinfo` text, if any.
///
/// Format (`proc(5)`): `id parent major:minor root mountpoint options
/// [optional fields...] - fstype source superoptions`. The separator `-`
/// is located explicitly because the number of optional fields varies.
pub fn cgroup2_mount_from_mountinfo(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(' ').collect();
        let sep = fields.iter().position(|f| *f == "-")?;
        let fstype = fields.get(sep + 1)?;
        if *fstype != "cgroup2" {
            return None;
        }
        fields.get(4).map(|m| unescape_octal(m))
    })
}

/// `mountinfo` escapes space, tab, newline and backslash as `\ooo`.
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|d| (b'0'..=b'7').contains(d))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The cgroup v2 mount point of this host, from `/proc/self/mountinfo`.
pub fn find_cgroup2_mount() -> std::io::Result<Option<String>> {
    Ok(cgroup2_mount_from_mountinfo(&std::fs::read_to_string(
        "/proc/self/mountinfo",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HYBRID: &str = "\
25 30 0:22 / /sys rw,nosuid shared:7 - sysfs sysfs rw
31 25 0:26 / /sys/fs/cgroup ro,nosuid shared:9 - tmpfs tmpfs ro,mode=755
33 31 0:28 / /sys/fs/cgroup/unified rw,nosuid shared:10 - cgroup2 cgroup2 rw
34 31 0:29 / /sys/fs/cgroup/cpu rw,nosuid shared:11 - cgroup cgroup rw,cpu
";

    #[test]
    fn the_v2_hierarchy_is_found_by_filesystem_type_not_by_path() {
        assert_eq!(
            cgroup2_mount_from_mountinfo(HYBRID).as_deref(),
            Some("/sys/fs/cgroup/unified")
        );
    }

    #[test]
    fn a_v1_only_host_has_no_v2_hierarchy() {
        let v1: String = HYBRID
            .lines()
            .filter(|l| !l.contains("cgroup2"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(cgroup2_mount_from_mountinfo(&v1), None);
    }

    #[test]
    fn optional_fields_do_not_shift_the_filesystem_type() {
        let line = "40 31 0:30 / /mnt/cg rw shared:1 master:2 unbindable - cgroup2 none rw\n";
        assert_eq!(
            cgroup2_mount_from_mountinfo(line).as_deref(),
            Some("/mnt/cg")
        );
    }

    #[test]
    fn an_escaped_mount_point_is_unescaped() {
        let line = "40 31 0:30 / /mnt/cg\\040v2 rw - cgroup2 none rw\n";
        assert_eq!(
            cgroup2_mount_from_mountinfo(line).as_deref(),
            Some("/mnt/cg v2")
        );
    }
}
