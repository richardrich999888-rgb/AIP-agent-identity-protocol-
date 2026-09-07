//! `emit-matrix` — generate `EVIDENCE_INDEPENDENCE_MATRIX.csv` from the code.
//!
//! Every derived column is read out of [`ProvenanceClass`] rather than typed
//! into a spreadsheet. A matrix maintained by hand drifts from the rules it
//! documents, and the drift is discovered by whoever trusts it last.
//!
//! Two columns are *declared* per tool rather than derived, because nothing in
//! the type system knows them:
//!
//! * `ONBOARD_OR_EXTERNAL` — where the thing physically sits.
//! * `INDEPENDENT_OF_SNIFFER_DOG?` — whether a defect in `aip-observe`'s own
//!   code would show up here as a disagreement. That is a fact about which
//!   mechanism a tool shares with the production observer, and it is written
//!   down per tool with its reason.
//!
//! Usage: `emit-matrix > ../../EVIDENCE_INDEPENDENCE_MATRIX.csv`

use vanian_external_adapter::ProvenanceClass;

/// One row: the tool, the class it maps to, and the two declared columns.
struct Row {
    source: &'static str,
    mechanism: &'static str,
    class: ProvenanceClass,
    placement: &'static str,
    independent_of_sniffer_dog: &'static str,
}

const ROWS: &[Row] = &[
    Row {
        source: "Robot telemetry (onboard odometry, joint state)",
        mechanism: "application code on the robot",
        class: ProvenanceClass::SubjectSelfReport,
        placement: "onboard",
        independent_of_sniffer_dog: "yes - shares no mechanism; but it is the subject, so its independence from the observer is not the useful question",
    },
    Row {
        source: "ROS 2 topic",
        mechanism: "DDS publish by a node the subject runs",
        class: ProvenanceClass::SubjectSelfReport,
        placement: "onboard",
        independent_of_sniffer_dog: "yes - different mechanism entirely",
    },
    Row {
        source: "ros2_tracing",
        mechanism: "LTTng tracepoints compiled into the subject's own processes",
        class: ProvenanceClass::SubjectMiddlewareInstrumentation,
        placement: "onboard",
        independent_of_sniffer_dog: "yes - LTTng userspace, not perf/netlink; a defect in aip-observe would show as disagreement",
    },
    Row {
        source: "Gazebo ground truth",
        mechanism: "simulator physics state",
        class: ProvenanceClass::SimulatorGroundTruth,
        placement: "external to the simulated robot, inside the simulation",
        independent_of_sniffer_dog: "yes - shares nothing",
    },
    Row {
        source: "rosbag2",
        mechanism: "durable recording of ROS 2 topics",
        class: ProvenanceClass::SubjectControlledRecording,
        placement: "onboard or adjacent",
        independent_of_sniffer_dog: "yes - but it records self-reports, so its independence buys nothing",
    },
    Row {
        source: "PX4 telemetry",
        mechanism: "flight-controller firmware",
        class: ProvenanceClass::SubjectSelfReport,
        placement: "onboard",
        independent_of_sniffer_dog: "yes - different mechanism",
    },
    Row {
        source: "MAVLink message stream",
        mechanism: "protocol transport for the above",
        class: ProvenanceClass::SubjectSelfReport,
        placement: "onboard, in transit",
        independent_of_sniffer_dog: "yes - a transport for a self-report is still a self-report",
    },
    Row {
        source: "MAVSDK",
        mechanism: "client library over MAVLink",
        class: ProvenanceClass::SubjectSelfReport,
        placement: "companion computer",
        independent_of_sniffer_dog: "yes - and it is a command surface, not an observer",
    },
    Row {
        source: "External camera (frames only, unanchored path)",
        mechanism: "image sensor outside the subject",
        class: ProvenanceClass::ExternalSensorUnanchored,
        placement: "external",
        independent_of_sniffer_dog: "yes - fully independent mechanism",
    },
    Row {
        source: "AprilTag/fiducial detection via an anchored collector",
        mechanism: "36h11 detection on a collector holding its own key",
        class: ProvenanceClass::ExternalSensorAnchored,
        placement: "external",
        independent_of_sniffer_dog: "yes - fully independent mechanism",
    },
    Row {
        source: "External tracking system (mocap, laser tracker, UWB)",
        mechanism: "an instrument outside the subject",
        class: ProvenanceClass::ExternalSensorUnanchored,
        placement: "external",
        independent_of_sniffer_dog: "yes - fully independent mechanism; unanchored in this build",
    },
    Row {
        source: "OPC UA server state",
        mechanism: "address space published by the control system",
        class: ProvenanceClass::ControllerAcknowledgement,
        placement: "onboard the control system",
        independent_of_sniffer_dog: "yes - and it is the subject's own model of the plant",
    },
    Row {
        source: "PLC / controller acknowledgement",
        mechanism: "response code from the controller",
        class: ProvenanceClass::ControllerAcknowledgement,
        placement: "onboard the control system",
        independent_of_sniffer_dog: "yes - different mechanism; still the subject answering",
    },
    Row {
        source: "AIRI event stream",
        mechanism: "signed, hash-chained events emitted by the agent",
        class: ProvenanceClass::SubjectSelfReport,
        placement: "onboard",
        independent_of_sniffer_dog: "yes - but it is the agent's account of itself, signed",
    },
    Row {
        source: "Sniffer Dog (aip-observe anchored collector)",
        mechanism: "Linux kernel facilities: pidfd+procfs, netlink connector, perf tracepoints, fanotify, AF_PACKET",
        class: ProvenanceClass::HostRuntimeObservation,
        placement: "external to the workload process, on the same host",
        independent_of_sniffer_dog: "NO - it is Sniffer Dog; a defect here is invisible to itself",
    },
    Row {
        source: "Linux audit subsystem",
        mechanism: "NETLINK_AUDIT syscall hooks",
        class: ProvenanceClass::HostRuntimeObservation,
        placement: "external to the workload process, on the same host",
        independent_of_sniffer_dog: "yes - a different kernel mechanism; corroborates the event, not just the reading",
    },
];

fn yn(b: bool) -> &'static str {
    if b {
        "YES"
    } else {
        "NO"
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn main() {
    println!(
        "SOURCE,MECHANISM,CONTROLS_SOURCE?,ONBOARD_OR_EXTERNAL,INDEPENDENT_OF_SUBJECT?,\
         INDEPENDENT_OF_SNIFFER_DOG?,MAX_EVIDENCE_CEILING,CAN_SUPPORT_EXECUTION?,\
         CAN_SUPPORT_PHYSICAL_EFFECT?,FAILURE_MODE,TRUST_ANCHOR?"
    );
    for r in ROWS {
        let c = r.class;
        let fields = [
            r.source.to_owned(),
            r.mechanism.to_owned(),
            // "Controls source" is asked from the subject's point of view: can
            // the thing under scrutiny alter what this says?
            format!("{} (subject)", yn(c.subject_controls_source())),
            r.placement.to_owned(),
            yn(c.is_external_to_subject()).to_owned(),
            r.independent_of_sniffer_dog.to_owned(),
            format!("{:?}", c.max_ceiling()),
            yn(c.can_support_execution()).to_owned(),
            yn(c.can_support_physical_effect()).to_owned(),
            c.failure_mode().to_owned(),
            yn(c.is_trust_anchor()).to_owned(),
        ];
        println!(
            "{}",
            fields
                .iter()
                .map(|f| csv_escape(f))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}
