use std::time::Duration;

use stun::transaction::{DEFAULT_MAX_RETRANSMITS, DEFAULT_RTO, FINAL_WAIT_RTO_MULTIPLIER};
use stun::RetransmitSchedule;

#[test]
fn default_schedule_matches_rfc5389_section_7_2_1() {
    let waits: Vec<u128> = RetransmitSchedule::new().map(|w| w.as_millis()).collect();
    assert_eq!(waits, [500, 1000, 2000, 4000, 8000, 16000, 8000]);

    let request_times: Vec<u128> = std::iter::once(0)
        .chain(waits[..waits.len() - 1].iter().scan(0, |sent_at, wait| {
            *sent_at += wait;
            Some(*sent_at)
        }))
        .collect();
    assert_eq!(request_times, [0, 500, 1500, 3500, 7500, 15500, 31500]);
    assert_eq!(waits.iter().sum::<u128>(), 39_500);

    assert_eq!(DEFAULT_RTO, Duration::from_millis(500));
    assert_eq!(DEFAULT_MAX_RETRANSMITS, 6);
    assert_eq!(FINAL_WAIT_RTO_MULTIPLIER, 16);
}

#[test]
fn custom_rto_scales_every_wait() {
    let waits: Vec<Duration> = RetransmitSchedule::with_rto(Duration::from_millis(3)).collect();
    assert_eq!(waits.len(), 7);
    assert_eq!(waits.iter().sum::<Duration>(), Duration::from_millis(3 * 79));
}

#[test]
fn zero_rto_yields_no_waits() {
    assert_eq!(RetransmitSchedule::with_rto(Duration::ZERO).count(), 0);
}
