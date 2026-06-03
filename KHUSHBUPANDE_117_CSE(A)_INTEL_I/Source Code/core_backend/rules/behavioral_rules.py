"""
Raksha Vision Core — Production Behavioral Rules Engine v2
==========================================================
260 production-grade rules across 8 categories.
Every rule: multi-condition logic, temporal requirement, confidence threshold,
suppression conditions. DRDO-grade — strict, not sensitive.

Categories:
  CRIME (60)  · SECURITY (60)  · BEHAVIOR (40)  · ANOMALY (40)
  BUSINESS (30) · SYSTEM (30)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RuleCategory(str, Enum):
    CRIME    = "CRIME"
    SECURITY = "SECURITY"
    BEHAVIOR = "BEHAVIOR"
    ANOMALY  = "ANOMALY"
    BUSINESS = "BUSINESS"
    CROWD    = "CROWD"      # kept for backward compat
    STAFF    = "STAFF"      # kept for backward compat
    SYSTEM   = "SYSTEM"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


@dataclass
class BehavioralRule:
    rule_id:        str
    name:           str
    description:    str
    category:       RuleCategory
    severity:       Severity
    tags:           List[str]
    action:         str
    trigger:        str
    risk_range:     tuple
    enabled:        bool = True
    cooldown_sec:   int  = 60


# ══════════════════════════════════════════════════════════
# CRIME RULES  CRM-001 → CRM-060
# ══════════════════════════════════════════════════════════
CRIME_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="CRM-001", name="Chain / Bag Snatching",
        description="Two persons in close proximity — one makes contact then flees at high speed. "
                    "Classic chain-snatching / bag-grab. Requires: proximity < threshold AND "
                    "one person velocity ≥ flee-threshold AND other person state IDLE/STANDING. "
                    "Temporal: 0.8 s continuous. Suppression: single person scene.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["snatching","chain-snatch","bag-snatch","robbery","fleeing"],
        trigger="dist<DIST_SNATCH AND fast.vel≥VEL_FLEE AND slow.state∈{IDLE,STANDING,WALKING} sustained 0.8s",
        action="Alert ALL security at exits immediately. Aid victim. Call police.",
        risk_range=(90,99), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="CRM-002", name="Physical Assault / Attack",
        description="Two persons in very close proximity with high combined velocity — punching, "
                    "beating, or physical attack. Requires: dist < fight-threshold AND both states "
                    "RUNNING/FLEEING AND combined velocity > 1.5× run-threshold. Temporal: 0.8 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["assault","attack","violence","fight","beating"],
        trigger="dist<DIST_FIGHT AND both RUNNING/FLEEING AND v_sum>VEL_RUN×1.5 sustained 0.8s",
        action="Deploy security immediately. Call police. Do not approach alone. Aid injured.",
        risk_range=(88,99), cooldown_sec=40,
    ),
    BehavioralRule(
        rule_id="CRM-003", name="Robbery / Mugging",
        description="Active aggressor engaging stationary victim at close range. Requires: "
                    "one person RUNNING/WALKING AND other person velocity < 0.5×walk-threshold "
                    "AND distance < 1.2×snatch-threshold. Temporal: 1.0 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["robbery","mugging","aggressor","victim","street-crime"],
        trigger="dist<DIST_SNATCH×1.2 AND v_max>VEL_RUN×0.8 AND v_min<VEL_WALK×0.5 sustained 1s",
        action="Alert security. Call police immediately. Do not put staff at risk.",
        risk_range=(85,99), cooldown_sec=40,
    ),
    BehavioralRule(
        rule_id="CRM-004", name="Pickpocketing / Distraction Theft",
        description="Two persons in very close standing contact at slow speed for sustained period. "
                    "Both non-fleeing, not at checkout. Requires: dist < 55px AND combined velocity "
                    "< 2.5×walk AND neither RUNNING/FLEEING/FALLEN. Temporal: 5 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["pickpocket","theft","close-contact","distraction-theft"],
        trigger="dist<55px AND v_sum<VEL_WALK×2.5 AND neither RUNNING/FLEEING AND not checkout sustained 5s",
        action="Alert plainclothes staff. Review footage. Observe both individuals.",
        risk_range=(68,85), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-005", name="Vehicle Theft / Car Crime",
        description="Person loitering in parking area > 3 minutes without entering a vehicle. "
                    "Requires: person in parking-zone AND displacement < loiter-threshold "
                    "AND dwell > 180 s AND no vehicle-entry event detected.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["vehicle-theft","car-crime","parking","break-in"],
        trigger="parking_zone=true AND dwell>180s AND displacement<LOITER_DISP",
        action="Alert security to check parking area. Request patrol.",
        risk_range=(62,82), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-006", name="Vandalism / Property Damage",
        description="Repetitive arm motion against a fixed surface. Requires: person STANDING "
                    "AND repetitive short-range motion against wall/display AND motion duration > 5 s "
                    "AND person not browsing merchandise.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["vandalism","graffiti","property-damage","criminal-damage"],
        trigger="repetitive close-range arm motion against fixed surface sustained >5s, velocity<VEL_WALK",
        action="Alert security. Document on camera. Approach carefully.",
        risk_range=(60,80), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-007", name="Stalking / Following",
        description="Person consistently following another at fixed distance. Requires: Person B "
                    "maintains 30–140px behind Person A for > 8 s while both WALKING/RUNNING "
                    "AND same direction vector.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["stalking","following","harassment","predatory","pursuit"],
        trigger="0.3×DIST_FOLLOW<dist<DIST_FOLLOW AND both mobile AND same_direction sustained 8s",
        action="Alert security. Do not confront alone. Warn potential victim discreetly.",
        risk_range=(65,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-008", name="Kidnapping / Forcible Removal",
        description="Two persons moving at high speed in same direction at close range. Requires: "
                    "dist < snatch-threshold AND both velocity ≥ run-threshold AND same direction "
                    "vector AND one person RUNNING, other RUNNING/WALKING. Temporal: 1.0 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["kidnapping","abduction","forcible-removal","hostage"],
        trigger="dist<DIST_SNATCH AND both mobile AND same_direction AND v_sum>VEL_RUN×2 sustained 1s",
        action="IMMEDIATE police alert. Do not lose visual. Block exits if safe.",
        risk_range=(92,99), cooldown_sec=40,
    ),
    BehavioralRule(
        rule_id="CRM-009", name="Domestic / Intimate Partner Violence",
        description="Two persons in repeated close aggressive interaction. Requires: dist < fight "
                    "AND asymmetric force: one fast, one slow AND repeated proximity oscillation "
                    "AND no checkout context. Temporal: 1.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["domestic-violence","intimate-partner","DV","abuse","assault"],
        trigger="dist<DIST_FIGHT AND v_asymmetry>2:1 AND repeated oscillation sustained 1.5s",
        action="Intervene with caution. Separate parties. Call police. Offer victim support.",
        risk_range=(85,98), cooldown_sec=40,
    ),
    BehavioralRule(
        rule_id="CRM-010", name="Sexual Harassment / Indecent Assault",
        description="One person repeatedly closing distance to another who is moving away. Requires: "
                    "Person A closes dist each frame AND Person B state WALKING away AND distance "
                    "< fight-threshold maintained despite B movement. Temporal: 2.0 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["sexual-harassment","indecent-assault","unwanted-contact"],
        trigger="A repeatedly closing distance to B who is WALKING away, dist<DIST_FIGHT sustained 2s",
        action="Intervene immediately. Separate parties. Call police. Offer victim support.",
        risk_range=(88,99), cooldown_sec=40,
    ),
    BehavioralRule(
        rule_id="CRM-011", name="Group Fight / Brawl",
        description="Three or more persons in tight cluster all running. Requires: 3+ persons "
                    "within DIST_CROWD AND all states RUNNING/FLEEING AND cluster_spread < threshold "
                    "AND scene is not sports context. Temporal: 1.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["fight","brawl","group-fight","gang-violence","melee"],
        trigger="3+persons cluster_spread<DIST_CROWD AND all RUNNING/FLEEING sustained 1.5s",
        action="Call police immediately. Alert all security. Clear bystanders. Do not engage.",
        risk_range=(86,99), cooldown_sec=40,
    ),
    BehavioralRule(
        rule_id="CRM-012", name="Weapon Drawn / Knife Attack",
        description="Person with arm-extension posture toward another person. Requires: arm-extension "
                    "gesture detected AND target person within 2m AND target person state changes "
                    "to FLEEING/FALLEN. Temporal: 0.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["weapon","knife","firearm","armed","blade","threat"],
        trigger="arm-extension toward person AND target FLEEING/defensive sustained 0.5s",
        action="DO NOT approach. Evacuate immediately. Call police. Lock down premises.",
        risk_range=(93,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-013", name="Surveillance / Pre-Crime Casing",
        description="Person stationary near high-value area for extended period watching activity. "
                    "Requires: dwell > 45 s AND displacement < loiter-threshold AND state IDLE/STANDING "
                    "AND no purchase action. Temporal: 45 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["casing","surveillance","reconnaissance","pre-crime","scouting"],
        trigger="state∈{IDLE,STANDING} AND dwell>45s AND displacement<LOITER_DISP sustained 45s",
        action="Approach and engage the person. Record appearance. Alert security.",
        risk_range=(58,78), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-014", name="Mob Formation / Group Aggression",
        description="3+ persons moving rapidly together. Requires: 3+ mobile persons AND average "
                    "velocity > 0.7×run-threshold AND cluster_spread < 2×DIST_CROWD. Temporal: 2 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["mob","gang","group-aggression","riot","organised-crime"],
        trigger="3+mobile AND avg_vel>VEL_RUN×0.7 AND cluster_spread<2×DIST_CROWD sustained 2s",
        action="Alert all security. Call police. Close entry points. Do not engage alone.",
        risk_range=(80,97), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="CRM-015", name="Fleeing from Scene",
        description="Person running at high speed toward exits — post-crime escape. Requires: "
                    "state=FLEEING AND velocity ≥ VEL_FLEE AND person heading toward exit zone "
                    "AND not sports context. Temporal: 1.5 s continuous.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["fleeing","escape","running","post-crime","suspect"],
        trigger="state=FLEEING AND vel≥VEL_FLEE sustained 1.5s. Blocked if IDLE/SITTING/STANDING.",
        action="Alert exit security immediately. Attempt intercept. Call police.",
        risk_range=(82,96), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="CRM-016", name="Sudden Acceleration / Panic Run",
        description="Person transitions from IDLE/STANDING/WALKING to RUNNING in < 1 second. "
                    "Requires: prev_state ∈ {IDLE,STANDING,WALKING} AND new_state ∈ {RUNNING,FLEEING} "
                    "AND velocity delta > threshold. Temporal: 0.5 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["sudden-movement","panic","acceleration","flight","evasion"],
        trigger="state_transition IDLE/STANDING/WALKING→RUNNING/FLEEING AND vel_delta>threshold sustained 0.5s",
        action="Investigate cause. Alert security. Review recent footage.",
        risk_range=(72,90), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="CRM-017", name="Drug Exchange / Dealing",
        description="Brief close contact between two persons with hand-exchange motion then rapid "
                    "departure. Requires: dist < 55px for < 3 s AND rapid separation after contact "
                    "AND both persons previously not interacting. Temporal: 2 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["drugs","dealing","exchange","hand-to-hand","narcotics"],
        trigger="brief_close_contact<3s AND rapid_separation AND prior_non_interaction",
        action="Record footage. Alert security. Contact police if confirmed.",
        risk_range=(60,82), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-018", name="Arson / Fire Setting Attempt",
        description="Person crouching near floor with repetitive low-motion gestures near combustible "
                    "area. Requires: state=SITTING/FALLEN AND near-floor proximity AND repetitive "
                    "motion < 10px/s sustained > 5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["arson","fire","incendiary","pyromania"],
        trigger="state=SITTING near floor AND repetitive gesture vel<10px/s sustained 5s",
        action="Alert security immediately. Evacuate. Call fire service and police.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-019", name="ATM / Kiosk Tampering",
        description="Person at payment terminal > 90 s without completing transaction. Requires: "
                    "person in payment-zone AND dwell > 90 s AND close proximity to terminal "
                    "AND no transaction-completion signal. Temporal: 90 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["ATM","card-fraud","skimmer","tampering","payment-crime"],
        trigger="payment_zone=true AND dwell>90s AND no_transaction_event",
        action="Alert security. Check terminal for skimmers. Notify bank.",
        risk_range=(65,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-020", name="Trespass / Unlawful Entry",
        description="Person entering through non-standard entry point (emergency exit, service door). "
                    "Requires: person detected in scene from non-main-entrance direction AND "
                    "entry not via authorised zone. Temporal: 1 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["trespass","break-in","unlawful-entry","burglary"],
        trigger="person_appears_in_scene from non-entry zone AND not normal_entry_path sustained 1s",
        action="Alert security and owner. Call police. Do not approach alone.",
        risk_range=(85,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-021", name="Smash-and-Grab Preparation",
        description="Person close to display case repeatedly examining it. Requires: dist to display "
                    "zone < 30px AND dwell > 60 s AND scanning motion pattern AND no staff present. "
                    "Temporal: 60 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["smash-grab","display","jewellery","organised-retail-crime"],
        trigger="in_display_zone AND dwell>60s AND scanning_motion AND no_staff_nearby",
        action="Alert security. Reinforce display area. Record individual.",
        risk_range=(65,84), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-022", name="Shoplifting — Item Concealment",
        description="Motion consistent with concealing merchandise — body turn, item disappears. "
                    "Requires: body-occlude motion AND no corresponding checkout visit "
                    "AND not at designated try-on zone. Temporal: 2 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["shoplifting","concealment","theft","retail-crime"],
        trigger="occlude_motion AND item_disappear AND no_checkout_visit sustained 2s",
        action="Alert security. Verify at exit. Do NOT confront alone.",
        risk_range=(78,97), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-023", name="Return Fraud / Price Tag Switching",
        description="Person manipulating price labels or barcodes. Requires: stationary AND close-range "
                    "repetitive hand motion on product surface AND motion duration > 10 s AND "
                    "not merchandise browsing context.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["fraud","price-tag","return-fraud","barcode","deception"],
        trigger="STANDING AND repetitive_hand_motion on product >10s AND not_browsing_pattern",
        action="Alert security to observe. Verify item at checkout.",
        risk_range=(55,78), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-024", name="Till / Cash Register Tampering",
        description="Unauthorised person accessing register area. Requires: non-staff in register-zone "
                    "OR unusual till motion pattern AND no transaction context. Temporal: 1 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["till-theft","cash","register","fraud","internal-theft"],
        trigger="non_staff_in_register_zone OR unusual_till_motion AND no_transaction sustained 1s",
        action="Alert manager. Review transaction log. Secure cash area.",
        risk_range=(80,97), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-025", name="Organised Retail Crime — Distraction Gang",
        description="Coordinated group: one occupies staff while others access merchandise. "
                    "Requires: 3+ persons AND one near staff AND two near high-value zone "
                    "simultaneously AND coordinated entry within 30 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["ORC","organised-crime","distraction-gang","coordinated-theft"],
        trigger="person_A near_staff AND persons_B_C in_high_value_zone AND coordinated_entry<30s",
        action="Alert ALL staff immediately. Lock high-value areas. Call police.",
        risk_range=(85,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-026", name="Repeat Offender / Known Suspect Re-entry",
        description="Individual re-identified who previously triggered a security alert. "
                    "Requires: re-ID match against alert-history > 80% confidence AND "
                    "prior alert was CRITICAL or HIGH severity.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["repeat-offender","re-entry","re-id","known-suspect","watchlist"],
        trigger="re_id_match>80% AND prior_alert_severity∈{CRITICAL,HIGH}",
        action="Alert security manager. Monitor from distance. Call police if warranted.",
        risk_range=(70,90), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-027", name="Counterfeit Currency / Document Fraud",
        description="Person with excessive note-handling time at checkout. Requires: at checkout AND "
                    "note-handling motion > 30 s AND unusual hold/examine pattern AND not counting.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["counterfeit","fraud","currency","document-fraud"],
        trigger="checkout_zone AND note_handle_motion>30s AND unusual_examine_pattern",
        action="Inspect notes under UV. Refuse if suspect. Call police.",
        risk_range=(65,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-028", name="Camera Tampering / CCTV Obstruction",
        description="Person pointing object at camera or causing sudden obstruction. Requires: "
                    "object moving toward camera lens OR sudden image coverage event. Temporal: 0.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["camera-tampering","CCTV","sabotage","obstruction"],
        trigger="object_approaching_lens OR sudden_coverage_event sustained 0.5s",
        action="Alert security. Switch to adjacent camera. Preserve footage.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-029", name="Child at Risk / Unaccompanied Minor",
        description="Child alone > 3 minutes or being handled aggressively. Requires: small-stature "
                    "person alone > 180 s OR adult grasping/leading small person at run speed.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["child-safety","safeguarding","unaccompanied-minor","child-exploitation"],
        trigger="small_stature alone>180s OR adult leading small_person at vel>VEL_RUN",
        action="Activate lost-child protocol. Alert security. Do not leave child alone.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-030", name="Human Trafficking Indicators",
        description="Group controlled by dominant individual with limited autonomous movement. "
                    "Requires: 3+ persons with one directing AND others showing restricted "
                    "movement radius AND no independent zone visits.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["human-trafficking","modern-slavery","exploitation","coercion"],
        trigger="1 controller + 2+ restricted-movement persons AND no_independent_movement",
        action="Alert police immediately. National Modern Slavery Hotline. Do not confront.",
        risk_range=(90,99), cooldown_sec=60,
    ),

    # ── CRM-031 to CRM-060 — Extended Crime Set ────────────────────────────────
    BehavioralRule(
        rule_id="CRM-031", name="Armed Robbery — Multiple Assailants",
        description="Multiple aggressors engaging one or more victims simultaneously. "
                    "Requires: 3+ persons in scene AND ≥2 in RUNNING state AND ≥1 near-stationary "
                    "victim AND cluster spreading (not converging). Temporal: 1.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["armed-robbery","multiple-assailants","gang-robbery","organised-violence"],
        trigger="3+persons AND 2+RUNNING AND 1+IDLE/STANDING-victim AND cluster_spread>threshold sustained 1.5s",
        action="Activate full lockdown. Police immediately. Do not intervene without armed backup.",
        risk_range=(95,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-032", name="Express Kidnapping — Forced ATM Withdrawal",
        description="Two persons at ATM — one controlling other under apparent duress. "
                    "Requires: 2 persons at ATM zone AND one stationary (victim) AND "
                    "one in aggressive proximity for > 60 s. Temporal: 60 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["express-kidnapping","ATM-robbery","forced-withdrawal","duress"],
        trigger="2persons at ATM AND one_stationary_victim AND aggressor_proximity>60s",
        action="Covert police alert. Do not startle suspect. Alert ATM operator.",
        risk_range=(92,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-033", name="Shoplifting — Grab and Run",
        description="Person grabs merchandise and immediately runs toward exit. "
                    "Requires: person in product zone transitions to FLEEING AND "
                    "heading toward exit AND no checkout path. Temporal: 0.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["grab-run","shoplifting","smash-grab","theft","exit"],
        trigger="product_zone→FLEEING→exit_direction AND no_checkout AND vel≥VEL_FLEE sustained 0.5s",
        action="Alert exit security immediately. Do not physically block. Call police.",
        risk_range=(90,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-034", name="Threatening Behaviour Toward Staff",
        description="Person in aggressive posture at close range to staff member. "
                    "Requires: person near staff zone AND state RUNNING/WALKING rapidly AND "
                    "staff member retreating. Temporal: 1.5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["staff-threat","aggression","violence","workplace-violence"],
        trigger="aggressor near_staff_zone AND staff_retreating AND vel>VEL_WALK sustained 1.5s",
        action="Deploy security. Evacuate staff to safe area. Call police.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-035", name="Extortion / Protection Racket",
        description="Recurring visits by same person demanding attention from business owner/staff. "
                    "Requires: same re-id visiting ≥3 times with approach-staff pattern AND "
                    "staff showing avoidance behavior.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["extortion","protection-racket","intimidation","organised-crime"],
        trigger="re_id_match AND 3+visits AND staff_avoidance_pattern",
        action="Alert manager. Document all incidents. Contact police with evidence.",
        risk_range=(70,88), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="CRM-036", name="Civil Unrest / Riot Onset",
        description="Rapid crowd velocity increase with objects thrown or property damage. "
                    "Requires: 5+ persons AND average velocity > VEL_RUN AND crowd density "
                    "increasing AND projectile motion detected. Temporal: 2 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["riot","civil-unrest","crowd-violence","mass-disorder"],
        trigger="5+persons AND avg_vel>VEL_RUN AND crowd_density_increasing sustained 2s",
        action="Evacuate premises. Lock all entry points. Call police (emergency).",
        risk_range=(93,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-037", name="Terrorist Surveillance — Premises Survey",
        description="Individual systematically photographing security infrastructure, entry/exit "
                    "points, and staff positions over extended period. "
                    "Requires: repeated stops at strategic positions AND camera-toward-security-feature "
                    "posture AND dwell > 5 min total.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["terrorism","surveillance","counter-terrorism","reconnaissance","IED"],
        trigger="systematic_position_stops AND security_infrastructure_observation AND total_dwell>300s",
        action="Alert security manager covertly. Do not approach. Contact anti-terrorism hotline.",
        risk_range=(80,97), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="CRM-038", name="Suspicious Package Placement",
        description="Person places object then deliberately departs without it. "
                    "Requires: person places object AND departs > 5m AND does not return "
                    "within 3 min AND object remains stationary. Temporal: 180 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["suspicious-package","IED","bomb-threat","left-behind"],
        trigger="object_placed AND owner_departed>5m AND object_stationary>180s",
        action="Clear the area. Do NOT touch. Call police bomb disposal.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-039", name="Impersonation of Staff / Security",
        description="Person wearing uniform-like clothing entering staff-only areas without authorisation. "
                    "Requires: person in restricted zone AND clothing matches staff pattern AND "
                    "no authorisation event logged. Temporal: 2 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["impersonation","social-engineering","unauthorised-access","fraud"],
        trigger="restricted_zone AND staff_appearance AND no_auth_event sustained 2s",
        action="Challenge identity. Request ID verification. Alert security manager.",
        risk_range=(72,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-040", name="Shoplifting — Booster Bag Usage",
        description="Person carrying oversized lined bag spending extended time near merchandise. "
                    "Requires: large-bag-detected AND extended product-zone dwell > 120 s AND "
                    "repeated merchandise contact without checkout.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["booster-bag","EAS-defeat","shoplifting","organised-retail"],
        trigger="large_bag AND product_zone_dwell>120s AND repeated_product_contact AND no_checkout",
        action="Alert EAS security. Check bag at exit. Alert security.",
        risk_range=(72,90), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-041", name="Internal Theft — Staff Product Removal",
        description="Staff member moving product toward non-standard exit. "
                    "Requires: staff-zone-origin AND product-carrying-posture AND heading to "
                    "non-checkout exit AND after-hours OR without transaction.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["internal-theft","staff-theft","shrinkage","employee-crime"],
        trigger="staff_id AND product_carrying AND non_checkout_exit AND no_transaction",
        action="Alert manager covertly. Review CCTV. Do not confront without evidence.",
        risk_range=(68,88), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-042", name="Till Fraud — Under-Ringing",
        description="Staff member performing transaction with unusually low register activity. "
                    "Requires: customer at checkout AND staff register-motion without standard "
                    "scan pattern AND no-beep event in transaction.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["till-fraud","under-ringing","employee-fraud","cash-fraud"],
        trigger="checkout_zone AND staff_transaction AND low_scan_rate AND no_standard_beep_pattern",
        action="Flag transaction. Alert manager. Review till video immediately.",
        risk_range=(65,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-043", name="After-Hours Burglary",
        description="Multiple persons inside premises during closed hours with tools or bags. "
                    "Requires: after-hours AND 2+ persons detected AND movement near high-value zones "
                    "AND no authorised after-hours access. Temporal: 5 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["burglary","after-hours","break-in","theft","organised"],
        trigger="after_hours AND 2+persons AND high_value_zone_movement AND no_auth sustained 5s",
        action="Silent police alert. Preserve footage. Do not enter premises.",
        risk_range=(95,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-044", name="Shelf Stripping — Organised Retail Crime",
        description="Group rapidly clearing entire shelf section. "
                    "Requires: 2+ persons at same shelf AND rapid repeated product-pick motion "
                    "AND carrying to bag AND no checkout intent. Temporal: 10 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["shelf-stripping","ORC","bulk-theft","organised-retail"],
        trigger="2+persons at_shelf AND rapid_product_pick AND bag_loading AND no_checkout sustained 10s",
        action="Alert all security. Block exits. Call police.",
        risk_range=(82,95), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-045", name="Identity Theft — Card Skimmer Plant",
        description="Person installing device on payment terminal. "
                    "Requires: person at terminal with tool-like hand motion AND terminal-cover "
                    "disturbance AND brief contact < 30 s then departure.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["card-skimmer","identity-theft","payment-fraud","ATM-crime"],
        trigger="terminal_zone AND tool_motion AND terminal_cover_disturbance AND brief_contact<30s",
        action="Check terminal immediately. Call bank. Alert police. Preserve as crime scene.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-046", name="Fraudulent Exchange / Con Artist",
        description="Person performing rapid hand movements during monetary exchange with confusion "
                    "tactics. Requires: at checkout/exchange point AND rapid hand switching "
                    "AND multiple items exchanged in < 10 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["con-artist","distraction-fraud","change-fraud","deception"],
        trigger="exchange_zone AND rapid_hand_switching AND multiple_items<10s",
        action="Alert cashier. Void transaction. Review footage.",
        risk_range=(65,85), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-047", name="Drug Use on Premises",
        description="Person in corner/blind spot with crouching posture and repeated arm-to-face "
                    "motion consistent with drug use. "
                    "Requires: isolated zone AND SITTING/FALLEN state AND arm-face motion > 30 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["drug-use","narcotics","illegal-substance","premises-crime"],
        trigger="isolated_zone AND SITTING AND arm_to_face_motion>30s AND no_purchase_context",
        action="Alert security. Request they leave. Call police if confirmed.",
        risk_range=(60,80), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-048", name="Indecent Exposure",
        description="Person in public area making unusual clothing-removal gesture. "
                    "Requires: STANDING AND downward clothing-removal motion AND "
                    "non-changing-room zone. Temporal: 2 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["indecent-exposure","public-order","sexual-offence"],
        trigger="non_dressing_zone AND clothing_removal_gesture AND STANDING sustained 2s",
        action="Alert security. Request departure. Call police. Protect witnesses.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-049", name="Aggressive Begging / Menacing",
        description="Person repeatedly approaching multiple individuals with confrontational posture. "
                    "Requires: same person approaches 3+ different individuals AND each approach "
                    "results in target avoidance AND person not staff.",
        category=RuleCategory.CRIME, severity=Severity.MEDIUM,
        tags=["aggressive-begging","menacing","intimidation","public-order"],
        trigger="3+target_approaches AND each_target_avoids AND not_staff AND sustained_pattern",
        action="Alert security. Request person to leave politely. Call police if refused.",
        risk_range=(45,65), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-050", name="Lock Picking / Entry Bypass Attempt",
        description="Person at door/lock with repetitive manipulation motion. "
                    "Requires: STANDING at door/lock AND repetitive tool-like motion < 3px/s "
                    "AND duration > 20 s AND no authorised access event.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["lock-picking","entry-bypass","burglary","break-in"],
        trigger="door_zone AND repetitive_tool_motion>20s AND no_auth_event",
        action="Alert security immediately. Call police. Lock down premises.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-051", name="Fire Exit Propping — Facilitated Entry",
        description="Person props emergency exit open and waits or signals. "
                    "Requires: emergency-exit-zone AND person STANDING with door open AND "
                    "signalling gesture toward outside AND dwell > 10 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["emergency-exit","facilitated-entry","accessory-theft","ORC"],
        trigger="emergency_exit_zone AND STANDING AND door_open>10s AND outward_signal_gesture",
        action="Close exit immediately. Alert security. Review who entered.",
        risk_range=(75,92), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-052", name="Graffiti / Tagging Attack",
        description="Person with spray-can arm motion against wall/fixture. "
                    "Requires: STANDING at wall AND arm sweeping motion pattern AND "
                    "no product in hand AND duration > 5 s.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["graffiti","tagging","vandalism","criminal-damage"],
        trigger="wall_proximity AND sweep_arm_motion>5s AND no_product_context",
        action="Alert security. Document. Approach carefully. Call police.",
        risk_range=(62,82), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-053", name="Vehicle Ramming Approach (Exterior)",
        description="Vehicle at high velocity heading toward premises entrance. "
                    "Requires: exterior-zone AND large-blob approaching at high speed "
                    "AND trajectory toward building entrance. Temporal: 0.3 s.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["vehicle-attack","ramming","terrorism","building-security"],
        trigger="exterior_zone AND large_blob_high_velocity AND entrance_trajectory sustained 0.3s",
        action="Immediate evacuation. Police. Block entrance if bollards available.",
        risk_range=(95,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-054", name="Social Engineering — Pretextual Access",
        description="Person gaining access to staff areas using deception (fake delivery, fake staff). "
                    "Requires: non-authorised person in staff/restricted zone AND carrying "
                    "prop-like object AND no prior authorisation.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["social-engineering","pretextual-access","insider-threat","deception"],
        trigger="restricted_zone AND prop_carrying AND no_auth_event AND non_staff_appearance",
        action="Challenge credentials. Request escort. Alert security manager.",
        risk_range=(68,88), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="CRM-055", name="Coordinated Distraction + Theft",
        description="Two-person operation: one creates commotion while partner steals. "
                    "Requires: Person A creates scene (argument, fall, noise) AND Person B "
                    "simultaneously accesses merchandise unattended.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["coordinated-theft","distraction","two-person-crime","ORC"],
        trigger="person_A_distraction_event AND person_B_merchandise_access_simultaneously",
        action="Alert all staff. Review all zones simultaneously. Call police.",
        risk_range=(85,97), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRM-056", name="Child Luring Attempt",
        description="Unknown adult attempting to engage with unaccompanied child persistently. "
                    "Requires: small-stature-alone AND adult approaching and re-approaching "
                    "despite child-retreat AND no family-group context.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["child-luring","child-protection","predatory","safeguarding"],
        trigger="small_stature_alone AND adult_repeated_approach AND child_retreat AND no_family_group",
        action="Intervene immediately. Separate adult from child. Call police.",
        risk_range=(92,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-057", name="Counterfeit Goods Operation",
        description="Person operating unofficial point of sale inside premises. "
                    "Requires: person with bag/box AND repeated hand-exchange with multiple "
                    "individuals AND no official checkout use.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["counterfeit-goods","illegal-trading","IP-crime","fraud"],
        trigger="large_bag AND repeated_hand_exchange AND multiple_individuals AND no_checkout",
        action="Alert management. Seize goods if legal. Call police.",
        risk_range=(65,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="CRM-058", name="Electrical / System Sabotage",
        description="Person accessing electrical panel, server cabinet, or power distribution area. "
                    "Requires: near electrical-zone AND tool-motion AND panel-access gesture "
                    "AND no maintenance-authorisation.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["sabotage","electrical","system-attack","infrastructure"],
        trigger="electrical_zone AND tool_motion AND panel_access AND no_maintenance_auth",
        action="Alert security and facilities immediately. Power isolation standby.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRM-059", name="Repeat Same-Day Re-entry — Reconnaissance",
        description="Individual entering 4+ times in one day without purchase. "
                    "Requires: re-ID ≥4 entries in < 8 hours AND zero checkout events AND "
                    "each visit to different zone.",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["reconnaissance","repeat-entry","casing","pre-crime"],
        trigger="4+entries in 8hrs AND zero_checkout AND different_zone_each_visit",
        action="Escalate to manager. Consider banning. Alert security on next entry.",
        risk_range=(68,85), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="CRM-060", name="Hostage / Duress Situation",
        description="Staff or customer being controlled under apparent threat. "
                    "Requires: person with restricted movement AND close-proximity controller "
                    "AND no independent movement for > 60 s AND stress indicators.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["hostage","duress","kidnapping","workplace-violence","terrorism"],
        trigger="target_restricted_movement AND close_controller AND no_independent_motion>60s",
        action="Silent police alert (999). Do not provoke. Evacuate if possible.",
        risk_range=(95,99), cooldown_sec=30,
    ),

    BehavioralRule(
        rule_id="CRM-FIGHT", name="Fight / Physical Violence Detected",
        description="Single tracked person showing violent motion signature — high directional "
                    "chaos, repeated velocity spikes (motion bursts), and sustained speed. "
                    "Catches fights where only one combatant is visible in frame. "
                    "Uses chaos score + motion burst count + velocity composite.",
        category=RuleCategory.CRIME, severity=Severity.CRITICAL,
        tags=["fight","violence","assault","physical-altercation","single-person"],
        trigger="chaos≥0.18 AND bursts≥1 AND vel≥VEL_WALK×0.15 — OR — bursts≥3 AND vel≥VEL_WALK×0.25",
        action="Respond immediately. Deploy security. Call police if assault confirmed.",
        risk_range=(65,97), cooldown_sec=25,
    ),

    BehavioralRule(
        rule_id="CRM-SUSP", name="Suspicious Aggressive Behaviour",
        description="Person displaying pre-assault indicators: sudden acceleration spike, "
                    "rapid approach toward another person, or aggressive flailing/gesturing. "
                    "Fires earlier than CRM-FIGHT — catches threatening confrontations "
                    "before physical contact. Lower confidence threshold (65–88%).",
        category=RuleCategory.CRIME, severity=Severity.HIGH,
        tags=["suspicious","aggressive","assault-precursor","threatening","confrontation"],
        trigger="sudden_accel>2× OR rapid_approach_to_person<DIST_SNATCH×2.2 OR chaos≥0.35",
        action="Monitor closely. Position security personnel. Be ready to intervene.",
        risk_range=(65,88), cooldown_sec=20,
    ),
]


# ══════════════════════════════════════════════════════════
# SECURITY RULES  SEC-001 → SEC-060
# ══════════════════════════════════════════════════════════
SECURITY_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="SEC-001", name="Loitering Detected",
        description="Person stationary in same zone > 60 s without clear purpose. "
                    "Requires: state ∈ {IDLE,STANDING} AND displacement < loiter-threshold "
                    "AND not queuing AND not checkout. Temporal: 60 s. "
                    "Suppression: person at checkout, browsing product.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["loitering","idle","zone","suspicious"],
        trigger="state∈{IDLE,STANDING} AND displacement<LOITER_DISP AND not_checkout sustained 60s",
        action="Send staff to greet/engage. Observe intent.",
        risk_range=(35,55), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-002", name="Theft Attempt — Item Concealment",
        description="Person concealing merchandise. Requires: item-disappear AND body-occlude-motion "
                    "AND no checkout registration AND not in authorised try-on zone.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["theft","concealment","shoplifting"],
        trigger="item_disappear AND body_occlude AND no_checkout AND not_try_on_zone",
        action="Alert security. Do NOT confront alone. Verify at exit.",
        risk_range=(80,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-003", name="Aggressive Posture / Threatening Behaviour",
        description="Rapid limb advance toward another person. "
                    "Requires: arm-extension toward person AND proximity < fight-threshold "
                    "AND velocity > walk-threshold. Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["aggression","threat","violence","confrontation"],
        trigger="arm_extension_toward_person AND dist<DIST_FIGHT AND vel>VEL_WALK sustained 1s",
        action="Deploy security. Consider calling police if escalating.",
        risk_range=(85,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-004", name="Tailgating — Unauthorised Entry",
        description="Second person follows authorised person through access gate without authentication. "
                    "Requires: two persons pass entry within 1.5 s AND only one badge event.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["tailgating","access-control","entry","piggybacking"],
        trigger="2persons pass_gate within 1.5s AND only_1_auth_event",
        action="Challenge second person. Lock zone if no response.",
        risk_range=(65,80), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-005", name="Restricted Zone Breach",
        description="Person inside staff-only or restricted area without authorisation. "
                    "Requires: centroid inside restricted-zone virtual perimeter AND "
                    "no authorisation event. Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["restricted","zone-breach","trespass","unauthorised"],
        trigger="centroid_in_restricted_zone AND no_auth_event sustained 1s",
        action="Alert security immediately. Monitor all zone exits.",
        risk_range=(70,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-006", name="Face Concealment Inside Premises",
        description="Person wearing full face covering (balaclava, scarf) inside store. "
                    "Requires: face-landmark confidence < 20% AND not medical-mask context "
                    "AND not culturally-exempt context.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["face-concealment","mask","balaclava","identity-hiding"],
        trigger="face_confidence<20% AND not_medical_mask AND not_cultural_exemption",
        action="Request identity verification politely. Escalate if refused.",
        risk_range=(60,82), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-007", name="Unattended Object",
        description="Bag/package left unattended > 2 min with owner departed. "
                    "Requires: static object > 120 s AND owner > 3m away AND object not shop fixture.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["unattended","object","left-behind","suspicious-package"],
        trigger="static_object>120s AND owner_departed>3m AND not_shop_fixture",
        action="Do NOT touch. Clear area. Call security to investigate.",
        risk_range=(62,80), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-008", name="Running Inside Premises",
        description="Person running at sustained speed indoors. "
                    "Requires: state=RUNNING AND velocity > VEL_RUN AND indoor context "
                    "AND not emergency evacuation. Temporal: 2 s.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["running","speed","indoors","safety"],
        trigger="state=RUNNING AND vel>VEL_RUN sustained 2s. Blocked if IDLE/SITTING/STANDING.",
        action="Monitor intent. Intercept if heading toward exit post-alert.",
        risk_range=(40,65), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="SEC-009", name="Perimeter Breach — After Hours",
        description="Motion detected inside premises outside operational hours. "
                    "Requires: person detected AND time ≥ 22:00 or < 07:00 AND "
                    "no authorised after-hours access. Temporal: 2 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["perimeter","after-hours","break-in","burglary","trespass"],
        trigger="person_detected AND (hour≥22 OR hour<7) AND no_auth_access sustained 2s",
        action="Alert owner and security. Consider calling police.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-010", name="Suspicious Item Handling",
        description="Person picks up, examines, and replaces high-value item 3+ times. "
                    "Requires: item pick/replace ≥ 3 times in 5 min AND same person "
                    "AND no checkout visit.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["suspicious","handling","high-value","assessment"],
        trigger="item_pick_replace≥3 in 5min AND same_person AND no_checkout",
        action="Send staff to assist. Monitor carefully.",
        risk_range=(38,60), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-011", name="Coordinated Group Distraction",
        description="Person occupies staff while another accesses merchandise. "
                    "Requires: person A near staff AND person B in merchandise zone "
                    "simultaneously AND coordinated entry.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["group","distraction","coordinated","theft"],
        trigger="person_A near_staff AND person_B in_merch_zone simultaneously AND cluster<70px sustained 3s",
        action="Alert all staff. Do not leave high-value areas unmonitored.",
        risk_range=(82,97), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-012", name="Repeated Same-Day Re-entry Without Purchase",
        description="Individual enters 3+ times in one day without purchasing. "
                    "Requires: re-ID ≥ 3 entries in < 8 hours AND zero checkout events.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["repeat-entry","reconnaissance","suspicious","no-purchase"],
        trigger="re_id 3+entries in 8hrs AND zero_checkout",
        action="Greet warmly on next entry. Note presence. Escalate if continues.",
        risk_range=(42,65), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SEC-013", name="Weapons / Dangerous Object Detection",
        description="Object consistent with weapon shape detected in hand/waist. "
                    "Requires: weapon-shape classifier > 75% confidence AND object in hand/waist "
                    "AND person not law-enforcement.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["weapon","knife","firearm","danger","armed"],
        trigger="weapon_shape_confidence>75% AND hand_or_waist_location AND not_law_enforcement",
        action="Evacuate nearby customers. Alert security and police immediately.",
        risk_range=(92,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-014", name="Customer Confrontation",
        description="Two persons in close aggressive proximity — argument or confrontation. "
                    "Requires: dist < 100px AND v_sum > VEL_WALK×1.5 AND both WALKING/RUNNING "
                    "AND not at checkout. Temporal: 2 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["fight","confrontation","customers","argument"],
        trigger="dist<100px AND v_sum>VEL_WALK×1.5 AND both WALKING/RUNNING sustained 2s",
        action="Dispatch staff to de-escalate. Security on standby.",
        risk_range=(70,90), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="SEC-015", name="Checkout Bypass",
        description="Person carrying merchandise toward exit without passing checkout. "
                    "Requires: merchandise-carrying posture AND exit-heading AND "
                    "no checkout zone dwell in session.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["bypass","exit","no-payment","theft","skip-checkout"],
        trigger="merchandise_carrying AND exit_heading AND no_checkout_dwell_in_session",
        action="Stop at exit politely. Check receipt. Alert if unresponsive.",
        risk_range=(72,90), cooldown_sec=60,
    ),

    # ── SEC-016 to SEC-060 — Extended Security Set ─────────────────────────────
    BehavioralRule(
        rule_id="SEC-016", name="Emergency Exit Forced Open",
        description="Emergency exit door opened from inside without alarm trigger. "
                    "Requires: person at emergency-exit zone AND door-open motion AND "
                    "no fire-alarm context. Temporal: 0.5 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["emergency-exit","forced-open","unauthorised-egress","security"],
        trigger="emergency_exit_zone AND door_open_motion AND no_fire_alarm sustained 0.5s",
        action="Alert security. Check who exited. Review whether door was propped.",
        risk_range=(80,95), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-017", name="Staff Area Breach — Service Corridor",
        description="Unauthorised person in service corridor or back-of-house area. "
                    "Requires: centroid in service-corridor zone AND no badge event "
                    "AND not known staff member. Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["staff-area","service-corridor","restricted","back-of-house"],
        trigger="service_corridor_zone AND no_badge_event AND not_staff sustained 1s",
        action="Intercept. Challenge identity. Alert security.",
        risk_range=(72,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-018", name="CCTV Blind Spot Exploitation",
        description="Person repeatedly positioning themselves in camera coverage gap. "
                    "Requires: person tracks edge of camera FOV AND dwell in marginal-zone > 30 s "
                    "AND repeated returns to same blind spot.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["blind-spot","camera-exploitation","CCTV","evasion"],
        trigger="marginal_zone_dwell>30s AND repeated_returns AND not_merchandise_context",
        action="Deploy mobile security to area. Review camera coverage.",
        risk_range=(65,82), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-019", name="Safe / Vault Area Proximity",
        description="Non-authorised person near safe or vault zone. "
                    "Requires: person in vault-proximity zone AND no authorisation "
                    "AND dwell > 10 s. Temporal: 10 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["safe","vault","cash-room","high-security-zone"],
        trigger="vault_proximity_zone AND no_auth AND dwell>10s",
        action="Challenge immediately. Alert security manager. Lock vault area.",
        risk_range=(85,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-020", name="Perimeter Fence / Wall Approach",
        description="Person approaching perimeter boundary at unusual time or angle. "
                    "Requires: centroid approaching boundary zone AND after-hours OR "
                    "trajectory toward non-entry point. Temporal: 3 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["perimeter","fence","boundary","intruder","approach"],
        trigger="boundary_zone_approach AND (after_hours OR non_entry_trajectory) sustained 3s",
        action="Alert perimeter security. Activate exterior lighting. Log.",
        risk_range=(70,88), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-021", name="Server Room / IT Infrastructure Access",
        description="Unauthorised person accessing IT infrastructure area. "
                    "Requires: server-room zone AND no auth AND tool or bag carried "
                    "AND dwell > 5 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["server-room","IT","cyber-physical","data-security"],
        trigger="server_room_zone AND no_auth AND tool_or_bag AND dwell>5s",
        action="Alert IT security and physical security. Lock IT room remotely.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-022", name="Suspicious Package Near Entry",
        description="Bag/box placed at entry/exit point by person who immediately leaves. "
                    "Requires: object placed at entry-zone AND person departs > 10m "
                    "AND object stationary > 60 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["suspicious-package","entry-point","IED","bomb","left-behind"],
        trigger="object_at_entry_zone AND owner_departed>10m AND object_stationary>60s",
        action="Evacuate entry area. Do NOT touch. Call police.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-023", name="Duress Signal from Staff",
        description="Staff member exhibiting distress behavior — unusual body language, "
                    "repeated gestures toward camera. "
                    "Requires: staff in scene AND repeated look-at-camera gesture AND unusual posture.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["staff-duress","distress","hostage","robbery","workplace-violence"],
        trigger="staff_zone AND repeated_camera_look AND unusual_posture AND context_alert",
        action="Silent police alert. Monitor. Dispatch support. Do not signal staff.",
        risk_range=(90,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-024", name="Multiple Failed Access Attempts",
        description="Person attempting entry via restricted door repeatedly without success. "
                    "Requires: same person at restricted entry ≥ 3 attempts AND no badge success "
                    "AND attempts within 5 min.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["access-control","failed-entry","brute-force","physical-intrusion"],
        trigger="3+failed_entry_attempts in 5min AND no_badge_success AND same_person",
        action="Alert security. Lock down access point. Identify person.",
        risk_range=(72,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-025", name="Person Hiding in Premises After Closing",
        description="Person concealing themselves in hidden area as closing commences. "
                    "Requires: person detected in low-traffic zone AND store-closing-time "
                    "AND minimal movement AND not authorised.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["hiding","after-hours","concealment","planned-burglary"],
        trigger="low_traffic_zone AND closing_time AND IDLE/SITTING AND no_auth",
        action="Systematic check of premises at closing. Call police if found.",
        risk_range=(85,97), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-026", name="Crowd Blockage at Emergency Exit",
        description="Emergency exit obstructed by crowd. "
                    "Requires: 3+ persons in emergency-exit zone AND low individual velocity "
                    "AND obstruction duration > 10 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["emergency-exit","blocked","fire-safety","evacuation","crowd"],
        trigger="3+persons in emergency_exit_zone AND avg_vel<VEL_WALK AND dwell>10s",
        action="Request crowd to clear exit. Notify fire safety officer.",
        risk_range=(72,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-027", name="Delivery Person Route Deviation",
        description="Delivery/service person accessing non-designated areas. "
                    "Requires: delivery-uniform detected AND centroid in non-delivery zone "
                    "AND dwell > 30 s.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["delivery","route-deviation","insider-threat","access-violation"],
        trigger="delivery_uniform AND non_delivery_zone AND dwell>30s",
        action="Challenge and redirect. Note identity. Alert manager.",
        risk_range=(45,65), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-028", name="Guard Post Abandonment",
        description="Designated guard position unoccupied during required hours. "
                    "Requires: guard-zone empty AND operational hours AND "
                    "absence > 5 min without break authorisation.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["guard","post-abandonment","security-gap","patrol"],
        trigger="guard_zone_empty AND operational_hours AND absence>300s",
        action="Alert security supervisor. Dispatch replacement immediately.",
        risk_range=(45,60), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SEC-029", name="Suspicious Vehicle — Prolonged Loitering",
        description="Vehicle stationary in car park or entry lane for excessive duration. "
                    "Requires: exterior camera AND large-stationary blob AND dwell > 10 min "
                    "AND no persons entering/exiting vehicle.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["suspicious-vehicle","loitering","surveillance","parking"],
        trigger="exterior_zone AND large_stationary_blob>600s AND no_person_activity",
        action="Patrol vehicle area. Note registration. Alert if suspicious.",
        risk_range=(45,65), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SEC-030", name="Contractor Without Escort in Restricted Zone",
        description="Contractor detected alone in restricted zone without authorised escort. "
                    "Requires: contractor-badge AND restricted-zone AND no escort within 3m "
                    "AND dwell > 30 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["contractor","escort","restricted-zone","compliance"],
        trigger="contractor_badge AND restricted_zone AND no_escort_within_3m AND dwell>30s",
        action="Alert security. Escort contractor back to permitted area.",
        risk_range=(65,80), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-031", name="Item Passed Over Physical Barrier",
        description="Object trajectory passes through/over security barrier. "
                    "Requires: object blob crossing barrier line AND two persons on either side "
                    "AND no authorised transaction.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["item-passed","barrier","security-bypass","theft"],
        trigger="object_crosses_barrier_line AND persons_both_sides AND no_auth_transaction",
        action="Alert security. Review footage. Challenge persons involved.",
        risk_range=(70,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-032", name="Turnstile / Gate Forced Entry",
        description="Person forcing through access gate without valid credential. "
                    "Requires: gate-zone AND rapid approach AND no badge event "
                    "AND entry motion detected. Temporal: 0.3 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["turnstile","forced-entry","access-control","breach"],
        trigger="gate_zone AND rapid_approach AND no_badge AND entry_motion sustained 0.3s",
        action="Alert security to intercept. Activate barrier alarm.",
        risk_range=(82,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-033", name="Counter-Surveillance Behaviour",
        description="Person systematically checking for surveillance — looking at cameras, "
                    "mirrors, staff positions repeatedly. "
                    "Requires: repeated camera/mirror glances AND altered routing after glance.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["counter-surveillance","awareness-check","pre-crime","evasion"],
        trigger="repeated_camera_glances AND route_alteration_after_glance AND pattern_sustained",
        action="Alert plainclothes security. Monitor closely. Prepare to intercept.",
        risk_range=(65,82), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="SEC-034", name="VIP Protection Zone Breach",
        description="Unauthorised person entering VIP or executive protection zone. "
                    "Requires: VIP-zone active AND non-authorised person entering "
                    "AND no clearance event. Temporal: 0.5 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["VIP","executive-protection","close-protection","breach"],
        trigger="vip_zone_active AND non_auth_person AND no_clearance sustained 0.5s",
        action="Close protection team alert. Intercept immediately.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-035", name="Large Bag / Luggage Brought In",
        description="Person entering with oversized luggage or bag inconsistent with shopping. "
                    "Requires: large-bag detected at entry AND bag size > standard shopping bag "
                    "AND not airport/transit context.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["large-bag","luggage","concealment","security-check"],
        trigger="large_bag_at_entry AND bag_size>threshold AND not_transit_context",
        action="Request bag check at entry. Alert security.",
        risk_range=(40,60), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-036", name="Visitor Overstay Past Closing Time",
        description="Non-staff person still in premises after closing. "
                    "Requires: closing-time AND person detected AND no staff-with-visitor event.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["overstay","closing-time","trespass","after-hours"],
        trigger="closing_time AND person_detected AND not_staff AND no_visitor_escort",
        action="Politely inform and escort out. Alert security if non-compliant.",
        risk_range=(68,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-037", name="Cash in Transit — Security Coverage",
        description="Cash transit operation detected without required security escort. "
                    "Requires: cash-bag-motion AND no security escort within 2m AND "
                    "not in secure transit area.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["cash-in-transit","CIT","robbery-risk","cash-handling"],
        trigger="cash_bag_motion AND no_security_escort AND not_secure_area",
        action="Halt transit. Alert security immediately. Escort to safe area.",
        risk_range=(88,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-038", name="Window / Display Case Physical Breach",
        description="Impact or forced opening of display case detected. "
                    "Requires: display-zone AND sudden motion burst AND prior static state "
                    "AND no authorised open event. Temporal: 0.2 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["display-case","smash-grab","break-in","jewellery","forced-entry"],
        trigger="display_zone AND sudden_motion_burst AND prior_static AND no_auth_open sustained 0.2s",
        action="Evacuate area. Call police. Lock down premises.",
        risk_range=(92,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-039", name="Evidence Destruction Attempt",
        description="Person attempting to destroy or remove CCTV or evidence. "
                    "Requires: person reaching toward recording equipment AND destructive motion "
                    "AND no maintenance authorisation.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["evidence-destruction","CCTV-tampering","obstruction","crime-cover"],
        trigger="reaching_toward_recording_equip AND destructive_motion AND no_maintenance_auth",
        action="Alert security. Preserve offsite backup immediately. Call police.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-040", name="Multiple Concurrent Zone Breaches",
        description="Two or more restricted zones simultaneously breached — possible coordinated attack. "
                    "Requires: 2+ restricted zones active AND different persons in each "
                    "AND within 30 s window.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["concurrent-breach","coordinated","multi-zone","security"],
        trigger="2+restricted_zones_active AND different_persons AND within_30s",
        action="Full security response. Lock all zones. Call police.",
        risk_range=(90,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-041", name="Hazardous Material Handling",
        description="Person with chemical container or hazmat-like object in non-designated area. "
                    "Requires: container-blob with liquid motion AND non-storage zone "
                    "AND no authorisation.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["hazmat","chemical","biological","dangerous-goods"],
        trigger="container_blob AND liquid_motion AND non_storage_zone AND no_auth",
        action="Alert facilities. Evacuate area if spill. Call hazmat if needed.",
        risk_range=(72,90), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-042", name="Physical Threat to Staff Member",
        description="Aggressive approach toward identified staff member. "
                    "Requires: staff in frame AND non-staff rapid advance toward staff "
                    "AND staff retreat AND close proximity. Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["staff-threat","workplace-violence","assault","employee-safety"],
        trigger="staff_detected AND non_staff_rapid_advance AND staff_retreating AND dist<DIST_FIGHT sustained 1s",
        action="Deploy security immediately. Separate individuals. Call police.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-043", name="Night Patrol Route Missed",
        description="Scheduled patrol route not completed within expected time window. "
                    "Requires: patrol-route zones not all visited AND patrol-window elapsed "
                    "AND no incapacitation alert.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["patrol","guard","route-missed","security-compliance"],
        trigger="patrol_zones_not_all_visited AND patrol_window_elapsed",
        action="Contact guard. Dispatch check. Review patrol log.",
        risk_range=(35,55), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SEC-044", name="Perimeter Alarm Zone Activation",
        description="Motion in alarm-designated outer perimeter zone. "
                    "Requires: outer-perimeter zone AND person detected AND "
                    "after-hours OR alarm-armed status. Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["perimeter-alarm","outer-zone","intrusion","sensor"],
        trigger="outer_perimeter_zone AND person_detected AND (after_hours OR alarm_armed) sustained 1s",
        action="Alert security and owner. Activate lighting. Call police.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-045", name="Loading Dock Unauthorised Entry",
        description="Person entering via loading dock in non-delivery hours. "
                    "Requires: loading-dock zone AND non-delivery-hours AND person detected "
                    "AND no delivery booking event.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["loading-dock","unauthorised","back-entry","trespass"],
        trigger="loading_dock_zone AND non_delivery_hours AND person AND no_delivery_booking",
        action="Alert security. Check delivery log. Challenge person.",
        risk_range=(72,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-046", name="System Override Attempt",
        description="Person at control panel with repetitive manipulation that matches "
                    "override pattern. "
                    "Requires: control-panel zone AND repetitive button-motion AND "
                    "no authorised maintenance. Temporal: 5 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["system-override","control-panel","sabotage","security-bypass"],
        trigger="control_panel_zone AND repetitive_button_motion>5s AND no_auth_maintenance",
        action="Alert security and engineering immediately. Disable remote override.",
        risk_range=(88,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-047", name="Evacuation Non-Compliance",
        description="Person remaining in premises during active evacuation. "
                    "Requires: evacuation-in-progress flag AND person detected AND "
                    "not moving toward exits AND not first-responder.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["evacuation","non-compliance","fire","emergency","safety"],
        trigger="evacuation_active AND person_detected AND not_exit_heading AND not_first_responder",
        action="Dispatch warden to locate and escort. Notify incident command.",
        risk_range=(72,90), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-048", name="Impersonation of Emergency Services",
        description="Person in uniform inconsistent with scheduled visit claiming emergency access. "
                    "Requires: uniform-detected AND unscheduled AND accessing restricted area "
                    "AND no prior coordination.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["impersonation","emergency-services","social-engineering","access"],
        trigger="uniform_detected AND unscheduled AND restricted_zone AND no_coordination",
        action="Verify credentials via official channel. Do not grant access unverified.",
        risk_range=(72,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-049", name="Roof Access Attempt",
        description="Person approaching roof access hatch or ladder. "
                    "Requires: roof-access zone AND person STANDING near ladder/hatch "
                    "AND upward motion AND no maintenance authorisation.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["roof-access","height","security","maintenance","intruder"],
        trigger="roof_access_zone AND upward_motion AND no_maintenance_auth",
        action="Alert security. Check roof access log. Intercept if no authorisation.",
        risk_range=(70,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-050", name="Person Down — Potential Medical Emergency",
        description="Person on ground unresponsive with no recovery movement. "
                    "Requires: FALLEN state AND velocity < 2px/s AND dwell in FALLEN > 5 s "
                    "AND no other person providing aid.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["medical","fallen","unconscious","emergency","first-aid"],
        trigger="state=FALLEN AND vel<2px/s AND fallen_dwell>5s AND no_aid_giver",
        action="Call ambulance immediately. First-aider to scene. Clear area.",
        risk_range=(92,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-051", name="Suspicious Drone / Aerial Surveillance",
        description="Small fast-moving aerial object detected near premises (exterior camera). "
                    "Requires: small high-velocity blob AND non-human aspect ratio AND "
                    "non-standard trajectory.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["drone","aerial-surveillance","privacy","counter-drone"],
        trigger="small_blob AND high_velocity AND aerial_aspect_ratio AND non_standard_trajectory",
        action="Alert security. Note direction of operation. Contact authorities if persistent.",
        risk_range=(65,82), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-052", name="Tamper with Fire Detection Equipment",
        description="Person reaching toward fire detector, sprinkler head, or fire panel. "
                    "Requires: fire-equipment zone AND reaching motion AND no maintenance auth "
                    "AND no fire event.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["fire-detection","tampering","arson","sabotage","fire-safety"],
        trigger="fire_equipment_zone AND reaching_motion AND no_auth AND no_fire_event",
        action="Alert security and fire safety officer. Verify equipment integrity.",
        risk_range=(82,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-053", name="Concealed Approach to Staff",
        description="Person approaching staff member from behind at high speed. "
                    "Requires: approach from behind staff AND vel > VEL_RUN AND "
                    "staff unaware (not turning). Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["ambush","staff-safety","behind-approach","assault-precursor"],
        trigger="behind_approach_staff AND vel>VEL_RUN AND staff_not_turning sustained 1s",
        action="Alert staff via discreet signal. Deploy security.",
        risk_range=(78,92), cooldown_sec=45,
    ),
    BehavioralRule(
        rule_id="SEC-054", name="Smoke / Haze Detection Event",
        description="Frame analysis detects significant haze or smoke-like visual pattern. "
                    "Requires: overall frame brightness variance increase AND haze pattern "
                    "AND no cleaning equipment in scene.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["smoke","fire","haze","emergency","evacuation"],
        trigger="frame_haze_pattern AND brightness_variance_increase AND no_cleaning_equip",
        action="Assume fire until confirmed otherwise. Evacuate. Call fire service.",
        risk_range=(90,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-055", name="Aggressive Queue Jumping",
        description="Person aggressively cutting into queue with confrontational posture. "
                    "Requires: person moves to front of queue-zone AND other persons move away "
                    "AND aggressive posture detected. Temporal: 3 s.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["queue-jumping","aggression","public-order","confrontation"],
        trigger="queue_front_jump AND others_retreat AND aggressive_posture sustained 3s",
        action="Staff to intervene politely. Security on standby.",
        risk_range=(38,58), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="SEC-056", name="Disruptive Behaviour on Premises",
        description="Person shouting, throwing objects, or causing disorder. "
                    "Requires: erratic rapid movement AND object throw event OR "
                    "aggressive posture for > 10 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["disruptive","disorder","anti-social","public-order"],
        trigger="erratic_movement AND (object_throw OR aggressive_posture>10s)",
        action="Request to leave. Call police if non-compliant.",
        risk_range=(65,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SEC-057", name="Intoxicated Person Presenting Risk",
        description="Person with staggering gait, falls, or aggressive behaviour suggesting intoxication. "
                    "Requires: erratic low-velocity movement AND balance-loss events AND "
                    "no medical context.",
        category=RuleCategory.SECURITY, severity=Severity.MEDIUM,
        tags=["intoxicated","drunk","drug-impaired","safety-risk"],
        trigger="stagger_gait AND balance_loss_events AND no_medical_context",
        action="Approach with care. Request to leave. Call ambulance if collapse.",
        risk_range=(45,65), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-058", name="Sudden Darkness — Lighting Manipulation",
        description="Deliberate extinguishing of lighting before suspicious activity. "
                    "Requires: sudden frame darkness AND person detected near light-switch zone "
                    "AND subsequent motion. Temporal: 1 s.",
        category=RuleCategory.SECURITY, severity=Severity.CRITICAL,
        tags=["lighting","darkness","pre-crime","sabotage","cover"],
        trigger="sudden_frame_darkness AND person_at_light_zone AND subsequent_motion sustained 1s",
        action="Activate emergency lighting. Alert security. Review footage.",
        risk_range=(85,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SEC-059", name="Person Photographing Security Infrastructure",
        description="Person pointing phone/camera toward security cameras, access panels, or alarms. "
                    "Requires: person STANDING AND hand held up toward security feature "
                    "AND sustained pointing > 5 s.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["reconnaissance","photo","security-survey","counter-intelligence"],
        trigger="STANDING AND hand_toward_security_feature AND sustained_pointing>5s",
        action="Alert security. Approach and ask purpose. Document.",
        risk_range=(65,82), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SEC-060", name="Person Refusing to Leave After Request",
        description="Individual remaining on premises after being asked to leave by staff. "
                    "Requires: staff-request event AND person still in premises AND "
                    "dwell > 5 min post-request.",
        category=RuleCategory.SECURITY, severity=Severity.HIGH,
        tags=["trespass","refusal","non-compliance","security"],
        trigger="staff_request_event AND person_still_in_premises AND post_request_dwell>300s",
        action="Call police for assistance. Document incident.",
        risk_range=(65,82), cooldown_sec=120,
    ),
]


# ══════════════════════════════════════════════════════════
# BEHAVIOR RULES  BEH-001 → BEH-040
# Suspicious behavioral patterns — not yet criminal, but
# statistically associated with pre-crime or risk events.
# ══════════════════════════════════════════════════════════
BEHAVIOR_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="BEH-001", name="Nervous / Anxious Behavioural Pattern",
        description="Person exhibiting high-frequency positional jitter with no forward progress — "
                    "pacing, fidgeting, repeated direction changes. "
                    "Requires: displacement > 0 AND net displacement ≈ 0 AND direction changes > 6 "
                    "in 30 s AND velocity 10–40px/s. Temporal: 30 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["nervous","anxious","fidgeting","pacing","pre-crime-indicator"],
        trigger="direction_changes>6 in 30s AND net_displacement≈0 AND vel∈(VEL_WALK×0.3,VEL_WALK×1.3) sustained 30s",
        action="Observe discretely. Send staff if behaviour persists.",
        risk_range=(30,52), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-002", name="Repeated Camera Watching",
        description="Person repeatedly looking toward CCTV cameras — awareness of surveillance. "
                    "Requires: head-turn toward camera positions ≥ 4 times in 60 s "
                    "AND not store-staff AND not casual glance pattern.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["camera-awareness","surveillance-consciousness","pre-crime","evasion"],
        trigger="camera_glance≥4 in 60s AND not_staff AND sustained_pattern",
        action="Alert security to observe closely. Counter-surveillance posture.",
        risk_range=(35,58), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-003", name="Systematic Layout Surveying",
        description="Person pausing at multiple strategic positions around the store in sequence "
                    "— mapping exits, cameras, staff positions. "
                    "Requires: ≥4 zone-stops in < 10 min AND each stop < 20 s AND "
                    "visits cover security-relevant locations.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["layout-survey","reconnaissance","casing","mapping","pre-crime"],
        trigger="4+strategic_zone_stops in 10min AND each_stop<20s AND security_relevant_locs",
        action="Alert security. Covertly observe. Prepare to intercept if theft follows.",
        risk_range=(52,72), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-004", name="Clothing Inappropriate for Scene / Season",
        description="Person wearing bulky or unseasonably heavy clothing that could conceal items — "
                    "overcoat in summer, multiple layers. "
                    "Requires: large-silhouette-for-temperature AND entry-time AND "
                    "heading toward merchandise.",
        category=RuleCategory.BEHAVIOR, severity=Severity.LOW,
        tags=["concealment-clothing","shoplifting-indicator","seasonal-anomaly"],
        trigger="large_clothing_silhouette AND seasonal_mismatch AND merchandise_heading",
        action="Note appearance. Alert plainclothes staff to observe.",
        risk_range=(20,42), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-005", name="Excessive Bag Checking / Concealment Gesture",
        description="Person repeatedly opens and closes bag near merchandise. "
                    "Requires: bag-open-close ≥ 3 in 60 s AND near merchandise AND "
                    "no receipt/purchase event. Temporal: 60 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["bag-checking","concealment","shoplifting-gesture","theft-indicator"],
        trigger="bag_open_close≥3 in 60s AND merchandise_zone AND no_purchase_event",
        action="Alert security to observe. Staff to offer assistance as pretext.",
        risk_range=(38,60), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-006", name="Unusual Entry / Exit Pattern",
        description="Person enters and exits multiple times using different doors. "
                    "Requires: 3+ entry events AND 2+ different access points used "
                    "AND within 15 min AND no clear purpose.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["unusual-entry","route-planning","evasion","multi-door"],
        trigger="3+entry_events AND 2+different_doors AND within_15min AND no_purpose",
        action="Alert security. Track movement pattern.",
        risk_range=(35,55), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-007", name="Refusing Staff Assistance Repeatedly",
        description="Person declines staff approach 3+ times while remaining in product zone. "
                    "Requires: staff-approach events ≥ 3 AND person declines each time "
                    "AND person remains in same zone AND no purchase.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["refusal","staff-avoidance","shoplifting-indicator","suspicious"],
        trigger="staff_approach≥3 AND decline_each AND person_remains AND no_purchase",
        action="Alert security. Observe from distance. Check at exit.",
        risk_range=(38,58), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-008", name="Observing Staff Patterns / Movements",
        description="Person watching staff routines — shift changes, till access, patrol routes. "
                    "Requires: person gaze tracked toward staff ≥ 5 times AND following staff "
                    "movement without approach AND no purchase intent.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["staff-surveillance","insider-threat","operational-reconnaissance","pre-crime"],
        trigger="staff_gaze≥5 AND staff_following_without_approach AND no_purchase",
        action="Alert security manager. Covertly shadow person.",
        risk_range=(52,72), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-009", name="Covert Recording of Premises",
        description="Person holding device at waist or low angle recording store layout, staff, "
                    "or security features. "
                    "Requires: device held at non-standard angle AND facing security features "
                    "AND no obvious legitimate use.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["covert-recording","surveillance","privacy","intelligence-gathering"],
        trigger="device_non_standard_angle AND facing_security_features AND not_social_media_use",
        action="Challenge politely. Request they stop. Alert security manager.",
        risk_range=(52,72), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-010", name="Extended Phone Use at Checkout / Register",
        description="Person at checkout with excessive phone use — possible communication with "
                    "accomplice or counterfeit-note signal. "
                    "Requires: checkout-zone AND phone-held-up > 30 s AND transaction in progress.",
        category=RuleCategory.BEHAVIOR, severity=Severity.LOW,
        tags=["phone-use","checkout","accomplice-signal","distraction"],
        trigger="checkout_zone AND phone_raised>30s AND transaction_in_progress",
        action="Staff awareness. Alert if unusual transaction follows.",
        risk_range=(18,38), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-011", name="Coded Meeting Behaviour — Hand Signals",
        description="Two persons exchanging apparent coded signals or specific hand gestures "
                    "without verbal interaction. "
                    "Requires: two persons in scene AND simultaneous hand gestures AND "
                    "no physical contact AND rapid separation after.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["hand-signals","coded-communication","gang","organised-crime","covert"],
        trigger="2persons AND simultaneous_hand_gestures AND no_contact AND rapid_separation",
        action="Alert security. Observe both persons separately.",
        risk_range=(38,58), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-012", name="Pacing / Agitated Repetitive Movement",
        description="Person pacing the same short path repeatedly — high stress or waiting for signal. "
                    "Requires: track shows repeated traversal of < 50px path AND ≥ 5 reversals "
                    "AND dwell > 60 s. Temporal: 60 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["pacing","agitated","stress","waiting","pre-crime"],
        trigger="path_length<50px AND reversals≥5 AND dwell>60s",
        action="Observe. Send staff if persists. Check if in contact with someone outside.",
        risk_range=(30,50), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-013", name="Crouching Behind Display / Shelving Unit",
        description="Person crouching in area concealed from main surveillance. "
                    "Requires: SITTING/FALLEN state AND zone with low camera visibility "
                    "AND dwell > 20 s AND no apparent purpose.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["crouching","concealment","hiding","theft-preparation","blind-spot"],
        trigger="SITTING_state AND low_vis_zone AND dwell>20s AND no_purpose",
        action="Alert security to physically check area. Deploy mobile guard.",
        risk_range=(58,78), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-014", name="Altered Gait — Possible Concealed Item",
        description="Person walking with asymmetric or constrained gait inconsistent with normal movement "
                    "— possible item concealed in clothing or between legs. "
                    "Requires: gait_asymmetry > threshold AND WALKING state AND entry was normal.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["altered-gait","concealment","shoplifting","constraint"],
        trigger="gait_asymmetry>threshold AND WALKING AND prior_normal_entry",
        action="Staff to intercept politely at exit. Check if receipt matches items.",
        risk_range=(38,60), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-015", name="Pre-Fight Posturing — Square-On Stance",
        description="Two persons face each other with square-on posture and raised tension. "
                    "Requires: two persons facing each other AND both STANDING AND "
                    "distance < fight-threshold AND minimal velocity (not walking away). Temporal: 5 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["pre-fight","posturing","confrontation","tension","aggression"],
        trigger="face_to_face AND both STANDING AND dist<DIST_FIGHT AND vel<VEL_WALK sustained 5s",
        action="Send staff to de-escalate before escalation. Security on standby.",
        risk_range=(55,75), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="BEH-016", name="Person Testing Security Response",
        description="Person commits minor infraction, observes response, then leaves and returns. "
                    "Requires: minor_violation event AND person observes staff response "
                    "AND person departs AND re-enters within 15 min.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["security-test","probing","pre-crime","intelligence-gathering","ORC"],
        trigger="minor_violation AND staff_response_observed AND departure AND re_entry<15min",
        action="Alert security manager. Heighten awareness. Log all activity.",
        risk_range=(58,78), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-017", name="Erratic Unpredictable Movement",
        description="Person with non-linear path and frequent direction changes inconsistent with "
                    "shopping — possible intoxication, mental health, or evasion. "
                    "Requires: path_linearity < 0.3 AND direction_changes > 8 in 30 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["erratic","unpredictable","intoxicated","mental-health","evasion"],
        trigger="path_linearity<0.3 AND direction_changes>8 in 30s",
        action="Approach with care. Assess welfare. Alert security if aggressive.",
        risk_range=(30,52), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-018", name="Apparent Medical Distress",
        description="Person showing signs of medical episode — clutching chest/head, "
                    "leaning on fixtures, unusual slow movement. "
                    "Requires: WALKING→IDLE with leaning posture AND FALLEN precursor state "
                    "AND dwell in slow-state > 10 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.CRITICAL,
        tags=["medical","distress","welfare","first-aid","emergency"],
        trigger="WALKING→slow_leaning AND fallen_precursor AND slow_state>10s",
        action="First-aider to scene immediately. Call ambulance. Clear space.",
        risk_range=(80,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="BEH-019", name="Overcrowding in Single Aisle",
        description="Excessive number of persons in a single narrow aisle — safety and theft risk. "
                    "Requires: 4+ persons in narrow-aisle zone AND dwell > 20 s AND "
                    "no special event context.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["aisle-overcrowding","safety","theft-cover","crush-risk"],
        trigger="4+persons in aisle_zone AND dwell>20s AND no_event_context",
        action="Staff to manage flow. Open adjacent aisle.",
        risk_range=(35,55), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-020", name="Deliberate Camera Avoidance Path",
        description="Person consistently routes around camera coverage zones. "
                    "Requires: person path avoids camera-coverage-areas AND "
                    "route is significantly longer than direct path AND pattern repeated.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["camera-avoidance","evasion","route-manipulation","surveillance-awareness"],
        trigger="path_avoids_coverage AND path_length>direct×1.5 AND pattern_repeated",
        action="Alert security. Track person. Ensure mobile coverage.",
        risk_range=(58,78), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-021", name="Goods Handover Between Persons Inside Store",
        description="Person A passes merchandise to Person B inside store without using checkout. "
                    "Requires: object passes from track A to track B AND no checkout event "
                    "AND not a gift context.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["goods-handover","relay-theft","pass-off","organised-retail"],
        trigger="object_transfer A→B AND no_checkout AND not_gift_context",
        action="Alert security. Check both persons at exit.",
        risk_range=(62,82), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-022", name="Person Sleeping on Premises",
        description="Person in SITTING/FALLEN state in non-seating area for extended period. "
                    "Requires: SITTING or FALLEN AND vel < 2px/s AND non-seating zone "
                    "AND dwell > 15 min.",
        category=RuleCategory.BEHAVIOR, severity=Severity.LOW,
        tags=["sleeping","loitering","welfare","trespass","homeless"],
        trigger="SITTING/FALLEN AND vel<2px/s AND non_seating_zone AND dwell>900s",
        action="Staff welfare check. Request to move on. Call support services if needed.",
        risk_range=(12,32), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BEH-023", name="Elderly Person Appearing Disoriented",
        description="Older person with slow, confused movement pattern — welfare concern. "
                    "Requires: slow velocity < VEL_WALK AND repeated direction reversals AND "
                    "dwell in same area > 5 min AND no companion.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["elderly","disoriented","welfare","dementia","safeguarding"],
        trigger="vel<VEL_WALK AND repeated_reversals AND area_dwell>300s AND no_companion",
        action="Welfare check from staff. Offer assistance. Contact family if needed.",
        risk_range=(22,45), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BEH-024", name="Child Separation from Guardian",
        description="Child separated from accompanying adult — lost child risk. "
                    "Requires: small-stature alone AND prior group context AND "
                    "adult companion disappeared AND child dwell > 90 s alone.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["child-separation","lost-child","safeguarding","welfare"],
        trigger="small_stature AND prior_group AND adult_gone AND alone_dwell>90s",
        action="Activate lost-child protocol immediately. Make PA announcement.",
        risk_range=(65,85), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="BEH-025", name="Self-Harm Risk Indicators",
        description="Person in isolated area exhibiting self-directed harm posture. "
                    "Requires: isolated-zone AND self-directed arm motion AND "
                    "SITTING/FALLEN state AND no interaction with others. Temporal: 10 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.CRITICAL,
        tags=["self-harm","mental-health","welfare","crisis","safeguarding"],
        trigger="isolated_zone AND self_directed_motion AND SITTING/FALLEN AND alone sustained 10s",
        action="Immediate welfare check. Do not leave alone. Call emergency services.",
        risk_range=(80,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="BEH-026", name="Group Standing Block — Deliberate Obstruction",
        description="Group of persons forming deliberate barrier blocking access. "
                    "Requires: 3+ persons in corridor/entry AND all STANDING AND "
                    "blocking flow of other persons AND dwell > 30 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["obstruction","blocking","crowd","deliberate","antisocial"],
        trigger="3+STANDING in corridor AND blocking_flow AND dwell>30s",
        action="Staff to politely request movement. Alert security if persistent.",
        risk_range=(30,50), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-027", name="Persistent Near High-Value Display",
        description="Person spending prolonged time near high-value items without purchase intent. "
                    "Requires: high-value-zone AND dwell > 90 s AND no pickup/examine with intent "
                    "AND state STANDING/IDLE. Temporal: 90 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["high-value","persistent-presence","jewellery","smash-grab-precursor"],
        trigger="high_value_zone AND STANDING/IDLE AND dwell>90s AND no_purchase_intent",
        action="Staff to approach and offer assistance. Security awareness.",
        risk_range=(35,58), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-028", name="Sudden Behaviour Change — Startle Response",
        description="Person suddenly changes posture/direction upon seeing security or staff — "
                    "guilty flight reflex. "
                    "Requires: state change to WALKING/RUNNING after staff-approach event AND "
                    "velocity increase > 50%.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["startle","flight-reflex","guilty-behaviour","evasion"],
        trigger="velocity_increase>50% AND direction_change after staff_approach_event",
        action="Security to observe. Follow at distance. Check at exit.",
        risk_range=(55,75), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-029", name="Excessive Time in Changing Room",
        description="Person in changing-room zone longer than normal browsing time. "
                    "Requires: changing-room zone AND dwell > 20 min AND no legitimate sale event.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["changing-room","shoplifting","tag-removal","booster-bag"],
        trigger="changing_room_zone AND dwell>1200s AND no_sale_event",
        action="Knock and check. Alert security. Check items brought in vs out.",
        risk_range=(38,60), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-030", name="Repeated Product Comparison Without Purchase",
        description="Person compares same two items more than 5 times — possible tag-switching "
                    "or assessment for concealment. "
                    "Requires: same items picked up > 5 times AND no checkout AND dwell > 5 min.",
        category=RuleCategory.BEHAVIOR, severity=Severity.LOW,
        tags=["product-comparison","tag-switch","assessment","no-purchase"],
        trigger="same_item_handled>5 AND no_checkout AND zone_dwell>300s",
        action="Staff to offer assistance. Monitor for tag manipulation.",
        risk_range=(18,40), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-031", name="Coordinated In-Store Communication",
        description="Multiple persons using phones or signals in coordinated pattern. "
                    "Requires: 2+ persons AND simultaneous phone use AND one near merchandise "
                    "AND one near exit AND temporal sync < 5 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["coordinated","phone","gang","organised-retail","communication"],
        trigger="2+persons AND simultaneous_phone AND one_merchandise AND one_exit AND sync<5s",
        action="Alert security. Observe both simultaneously. Intercept at exit.",
        risk_range=(58,78), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-032", name="Person Using Store as Shelter Without Purchase",
        description="Person present for extended period clearly not shopping — sheltering. "
                    "Requires: dwell > 45 min AND zero zone variety AND zero purchase AND "
                    "not staff or service worker.",
        category=RuleCategory.BEHAVIOR, severity=Severity.LOW,
        tags=["sheltering","loitering","non-customer","trespass"],
        trigger="dwell>2700s AND zero_zone_variety AND zero_purchase AND not_staff",
        action="Welfare check. Offer assistance. Politely ask to move on.",
        risk_range=(10,28), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BEH-033", name="Object Placement Surveillance — Table/Counter",
        description="Person places object (phone/device) facing security equipment or staff area "
                    "and steps away — covert recording device. "
                    "Requires: object placed AND person steps > 2m away AND object facing "
                    "security feature AND person returns after > 2 min.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["covert-device","recording","surveillance","counter-intelligence"],
        trigger="object_placed_facing_security AND person_away>2m AND return_after>120s",
        action="Alert security manager. Check object. Preserve as evidence.",
        risk_range=(65,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-034", name="Suspicious Interaction at Blind Spot",
        description="Two persons meeting in low-camera-coverage zone. "
                    "Requires: 2 persons in coverage-gap zone AND brief close contact "
                    "AND rapid separation AND no obvious shopping context.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["blind-spot","covert-meeting","exchange","drugs","theft"],
        trigger="2persons in coverage_gap AND brief_contact AND rapid_separation AND no_shopping",
        action="Deploy mobile security to area. Review all available footage.",
        risk_range=(55,75), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-035", name="Following Staff Member (Non-customer)",
        description="Person closely following staff member through non-public areas. "
                    "Requires: person state WALKING AND same direction as staff AND "
                    "distance < DIST_FOLLOW AND not customer-service interaction. Temporal: 10 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["staff-following","insider-threat","stalking","access-seeking"],
        trigger="following_staff AND same_direction AND dist<DIST_FOLLOW AND not_service_context sustained 10s",
        action="Alert security. Intercept and challenge. Escort away.",
        risk_range=(58,78), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-036", name="Excessive Dwell at Entry / Exit",
        description="Person waiting at entry/exit without entering or leaving for extended period. "
                    "Requires: entry-zone AND IDLE/STANDING AND dwell > 60 s AND "
                    "no greeter context.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["entry-dwell","loitering","surveillance","lookout"],
        trigger="entry_exit_zone AND IDLE/STANDING AND dwell>60s AND no_greeter_context",
        action="Challenge or engage. Possible lookout role.",
        risk_range=(35,55), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-037", name="Removing Price / Security Tags from Merchandise",
        description="Person making repeated picking motion on product consistent with tag removal. "
                    "Requires: product in hand AND repetitive pick motion AND STANDING "
                    "AND no checkout zone.",
        category=RuleCategory.BEHAVIOR, severity=Severity.HIGH,
        tags=["tag-removal","EAS","price-tag","shoplifting-preparation"],
        trigger="product_in_hand AND repetitive_pick_motion AND not_checkout_zone",
        action="Alert security. Observe to exit. Check item.",
        risk_range=(65,85), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BEH-038", name="Wearing Hood / Peaked Cap Obscuring Face Indoors",
        description="Person wearing hood or deep-peaked cap pulled low obscuring face features. "
                    "Requires: face-landmark confidence < 40% AND cap/hood occlusion pattern "
                    "AND person actively avoiding cameras.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["face-occlusion","hood","cap","identity-hiding","suspicious"],
        trigger="face_confidence<40% AND cap_hood_pattern AND camera_avoidance",
        action="Note appearance. Alert security. Request to remove hood if policy permits.",
        risk_range=(38,60), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BEH-039", name="Locker Area Unusual Activity",
        description="Person spending extended time at public locker area with unusual "
                    "open/close frequency — possible item storage or retrieval for theft. "
                    "Requires: locker-zone AND dwell > 5 min AND open-close events > 3.",
        category=RuleCategory.BEHAVIOR, severity=Severity.MEDIUM,
        tags=["locker","storage","theft","ORC","merchandise-concealment"],
        trigger="locker_zone AND dwell>300s AND open_close>3",
        action="Security to observe locker zone. Challenge unusual activity.",
        risk_range=(35,55), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="BEH-040", name="Crowd Tunnel Vision — Stampede Precursor",
        description="Large group of persons all orienting and moving in same direction rapidly "
                    "— crowd psychology event, possible panic. "
                    "Requires: 5+ persons AND velocity alignment > 85% AND avg_vel > VEL_WALK "
                    "AND same direction. Temporal: 3 s.",
        category=RuleCategory.BEHAVIOR, severity=Severity.CRITICAL,
        tags=["stampede","crowd-psychology","panic","evacuation","mass-casualty"],
        trigger="5+persons AND vel_alignment>85% AND avg_vel>VEL_WALK AND same_direction sustained 3s",
        action="Open all exits. Clear path. PA announcement. Emergency services standby.",
        risk_range=(80,97), cooldown_sec=30,
    ),
]


# ══════════════════════════════════════════════════════════
# ANOMALY RULES  ANO-001 → ANO-040
# Statistical / spatial / temporal anomalies detected by
# pattern analysis — not direct behavioural observation.
# ══════════════════════════════════════════════════════════
ANOMALY_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="ANO-001", name="Unexpected Crowd Thinning",
        description="Rapid drop in occupancy count without normal exit flow — possible threat causing "
                    "silent evacuation. "
                    "Requires: occupancy drops > 40% in < 60 s AND exit traffic below expected "
                    "AND no scheduled event.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["crowd-thinning","silent-evacuation","threat-response","anomaly"],
        trigger="occupancy_drop>40% in 60s AND low_exit_traffic AND no_scheduled_event",
        action="Alert security. Check for unreported threat. Staff sweep.",
        risk_range=(65,85), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-002", name="Simultaneous Multi-Exit Movement",
        description="Multiple persons heading toward all exits simultaneously — coordinated exit or panic. "
                    "Requires: 3+ exits active AND persons in each AND simultaneous movement "
                    "AND not closing-time.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["multi-exit","coordinated","panic","anomaly","crowd"],
        trigger="3+exits_active AND persons_each_exit AND simultaneous AND not_closing_time",
        action="Alert security. Identify cause. PA if warranted.",
        risk_range=(62,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-003", name="Counter-Flow — Against Normal Traffic Direction",
        description="Person moving against the established customer flow direction at high speed. "
                    "Requires: person velocity in counter-flow direction AND vel > VEL_WALK "
                    "AND not authorised staff. Temporal: 3 s.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["counter-flow","anomalous-movement","crowd-behavior","safety"],
        trigger="counter_flow_direction AND vel>VEL_WALK AND not_staff sustained 3s",
        action="Observe for cause. Alert security if continues.",
        risk_range=(35,55), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="ANO-004", name="Velocity Distribution Anomaly",
        description="Scene average velocity deviates significantly from baseline for this time of day. "
                    "Requires: scene_avg_vel > 2×baseline_for_hour AND person count > 2 "
                    "AND sustained > 5 s.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["velocity-anomaly","baseline-deviation","statistical","crowd-behavior"],
        trigger="scene_avg_vel>2×baseline AND count>2 AND sustained>5s",
        action="Review scene. Dispatch security.",
        risk_range=(40,60), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="ANO-005", name="Dead Zone Avoidance Pattern",
        description="All persons in scene systematically avoiding a specific zone — possible threat "
                    "in that zone. "
                    "Requires: zone has zero traffic AND surrounding zones active AND pattern > 3 min.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["zone-avoidance","anomaly","threat-presence","behavioral-indicator"],
        trigger="zone_zero_traffic AND surrounding_zones_active AND pattern>180s",
        action="Physical security check of avoided zone. Investigate cause.",
        risk_range=(60,80), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-006", name="Synchronized Entry Pattern",
        description="Multiple persons entering within seconds of each other from same direction — "
                    "coordinated entry. "
                    "Requires: 3+ persons enter within 10 s AND same entry point AND "
                    "no queue-context.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["synchronized-entry","coordinated","gang","ORC","flood-entry"],
        trigger="3+entry_events within 10s AND same_entry AND no_queue_context",
        action="Alert security immediately. Monitor each person independently.",
        risk_range=(65,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-007", name="Abnormal Footfall Spike",
        description="Footfall rate exceeds 3× the hourly baseline for this day/time. "
                    "Requires: entry_rate > 3×baseline AND no promotional event AND "
                    "sustained > 5 min.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["footfall-spike","capacity","anomaly","security","staffing"],
        trigger="entry_rate>3×baseline AND no_promo_event AND sustained>300s",
        action="Alert manager. Increase security and staff coverage.",
        risk_range=(35,55), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="ANO-008", name="Camera Shake / Vibration Anomaly",
        description="Frame analysis detects camera motion inconsistent with normal vibration — "
                    "possible impact, tampering, or structural event. "
                    "Requires: frame-shift > threshold AND no scheduled maintenance "
                    "AND pattern not wind-vibration.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["camera-shake","tampering","structural","vibration","anomaly"],
        trigger="frame_shift>threshold AND no_maintenance AND not_wind_pattern",
        action="Check camera mounting. Alert security. Review recent footage.",
        risk_range=(62,80), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-009", name="Sudden Illumination Change",
        description="Abrupt change in frame brightness not matching time-of-day or weather. "
                    "Requires: brightness_delta > 40% in < 1 s AND no scheduled lighting-change "
                    "AND camera not sun-flare pattern.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["illumination","brightness-anomaly","power","lighting","anomaly"],
        trigger="brightness_delta>40% in 1s AND no_scheduled_lighting AND not_sun_flare",
        action="Check lighting system. Alert facilities if power issue.",
        risk_range=(35,55), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-010", name="Motion in Confirmed Empty Zone",
        description="Motion detected in zone confirmed empty by manual security sweep. "
                    "Requires: zone_clear flag set AND motion_blob detected AND "
                    "not cleaning-robot context. Temporal: 1 s.",
        category=RuleCategory.ANOMALY, severity=Severity.CRITICAL,
        tags=["ghost-motion","concealed-person","hiding","anomaly","after-hours"],
        trigger="zone_clear_flag AND motion_blob_detected AND not_robot sustained 1s",
        action="Alert security. Recheck zone immediately.",
        risk_range=(85,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="ANO-011", name="Repeated Identical Path Pattern",
        description="Same track pattern repeated multiple times — rehearsal for crime or OCD. "
                    "Requires: path_similarity > 85% across ≥ 3 traversals AND same person re-id.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["repeated-path","rehearsal","pre-crime","anomaly","ORC"],
        trigger="path_similarity>85% AND 3+traversals AND same_re_id",
        action="Alert security. Observe intent.",
        risk_range=(38,58), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="ANO-012", name="Crowd Wave / Shockwave Pattern",
        description="Ripple of movement spreading outward from point — possible fight, threat, "
                    "or collapse causing crowd reaction. "
                    "Requires: velocity wave radiating from point AND > 3 persons affected "
                    "AND not entrance-entry flow.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["crowd-wave","shockwave","threat","fight","anomaly","crowd-behavior"],
        trigger="velocity_wave_radial AND 3+persons_affected AND not_entry_flow",
        action="Identify wave origin. Dispatch security to centre point.",
        risk_range=(65,85), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-013", name="Abnormal Zone Dwell Distribution",
        description="Single zone absorbing disproportionate share of customer dwell time today "
                    "versus historical baseline. "
                    "Requires: zone_dwell_share > 3×baseline AND > 2 persons affected AND sustained.",
        category=RuleCategory.ANOMALY, severity=Severity.LOW,
        tags=["dwell-distribution","zone-anomaly","business","layout"],
        trigger="zone_dwell_share>3×baseline AND 2+persons AND sustained",
        action="Review zone. Check product, signage, blockage.",
        risk_range=(10,30), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="ANO-014", name="Entry–Exit Count Imbalance",
        description="Significantly more entries than exits tracked — persons not accounted for. "
                    "Requires: entry_count > exit_count + threshold AND tracking_mature "
                    "AND not peak-time lag.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["count-imbalance","occupancy","missing-persons","anomaly"],
        trigger="entry_count > exit_count + N AND tracking_stable AND not_peak_lag",
        action="Reconcile manually. Check for unreported persons remaining on premises.",
        risk_range=(35,55), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="ANO-015", name="Track Merge / ID Collision Anomaly",
        description="Two tracks merge into one without clear exit of one person — possible "
                    "tracking fault masking a person. "
                    "Requires: two tracks converge AND one disappears AND one continues "
                    "without occlusion explanation.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["track-merge","tracking-error","occlusion","person-count","anomaly"],
        trigger="2tracks_converge AND 1_disappears AND no_occlusion_event",
        action="Flag tracking gap. Increase detection sensitivity in area.",
        risk_range=(25,45), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-016", name="Perimeter Walk Pattern",
        description="Person systematically walking the perimeter of the premises interior "
                    "— mapping boundaries or looking for weak points. "
                    "Requires: track follows wall-adjacent path AND covers > 60% perimeter "
                    "AND no merchandise contact.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["perimeter-walk","reconnaissance","casing","mapping","anomaly"],
        trigger="wall_adjacent_path AND perimeter_coverage>60% AND no_merch_contact",
        action="Alert security. Follow discretely. High casing indicator.",
        risk_range=(60,80), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="ANO-017", name="Systematic Shelf Bypass Pattern",
        description="Person walks all aisles systematically without examining products — "
                    "unusual for genuine shopper. "
                    "Requires: aisle traversal > 5 aisles AND no item pickup AND "
                    "traverse time < 30 s per aisle.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["shelf-bypass","systematic","anomaly","reconnaissance","shoplifting-survey"],
        trigger="5+aisles_traversed AND no_pickup AND <30s_per_aisle",
        action="Observe. Possible merchandise survey before theft attempt.",
        risk_range=(32,52), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="ANO-018", name="Checkout Avoidance Pattern",
        description="Person has collected items and routes around checkout consistently. "
                    "Requires: items-held AND path routes around checkout zone ≥ 2 times "
                    "AND heading toward exit.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["checkout-avoidance","theft","anomaly","no-pay"],
        trigger="items_held AND checkout_bypass≥2 AND exit_heading",
        action="Alert exit security. Intercept for receipt check.",
        risk_range=(70,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-019", name="Multiple Simultaneous Incidents",
        description="Two or more distinct alert events occurring within 30 s — possible "
                    "coordinated attack or system anomaly. "
                    "Requires: 2+ independent alert-firing events within 30 s window.",
        category=RuleCategory.ANOMALY, severity=Severity.CRITICAL,
        tags=["simultaneous-incidents","coordinated","multi-threat","anomaly"],
        trigger="2+alert_events within 30s AND independent_triggers",
        action="Full security response. All staff alert. Police standby.",
        risk_range=(85,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="ANO-020", name="Zone Traffic Flow Reversal",
        description="Direction of crowd flow through a zone has reversed from historical norm — "
                    "possible blocked exit or threat driving crowd back. "
                    "Requires: flow_direction ≠ historical AND sustained > 30 s AND > 2 persons.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["flow-reversal","crowd","anomaly","blocked-exit","threat-driven"],
        trigger="flow_direction!=historical AND sustained>30s AND 2+persons",
        action="Investigate cause. Check blocked exits. Alert security.",
        risk_range=(60,80), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="ANO-021", name="Queue Abandonment Wave",
        description="Multiple persons simultaneously leaving checkout queue — severe service failure "
                    "or external threat. "
                    "Requires: 3+ persons leave checkout-zone within 20 s AND not completed transaction.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["queue-abandonment","service-failure","anomaly","crowd-behavior"],
        trigger="3+persons leave checkout within 20s AND no_transaction_complete",
        action="Manager to investigate. Open more checkouts or assess threat.",
        risk_range=(30,50), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-022", name="Gait Inconsistency — Possible Injury or Concealment",
        description="Person's gait pattern changes significantly mid-tracking session. "
                    "Requires: gait_asymmetry_delta > 30% AND WALKING state AND no prior FALLEN event.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["gait-change","injury","concealment","anomaly","welfare"],
        trigger="gait_asymmetry_delta>30% AND WALKING AND no_prior_fall",
        action="Staff welfare check. Could be injury or concealed item.",
        risk_range=(30,50), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-023", name="Group Disbanding Suddenly",
        description="Group of persons together suddenly disperses in all directions — possible "
                    "post-crime scatter tactic or panic. "
                    "Requires: 3+ persons in cluster AND cluster_spread increases > 200% in < 5 s.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["group-disband","scatter","post-crime","panic","ORC"],
        trigger="3+persons_clustered AND cluster_spread_increase>200% in 5s",
        action="Alert security. Review immediately preceding footage for triggering event.",
        risk_range=(65,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-024", name="Temporal Pattern Anomaly — Same Time Daily",
        description="Suspicious event recurring at same time on multiple days — scheduled crime. "
                    "Requires: same alert type fires within ±15 min on 3+ consecutive days.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["temporal-pattern","scheduled-crime","repeat","daily","anomaly"],
        trigger="same_alert_type within ±15min on 3+consecutive_days",
        action="Increase security coverage at that time window proactively.",
        risk_range=(65,85), cooldown_sec=86400,
    ),
    BehavioralRule(
        rule_id="ANO-025", name="Cross-Camera Re-appearance Speed Anomaly",
        description="Person re-identified on distant camera faster than physically possible — "
                    "tracking ghost or cloned identity. "
                    "Requires: re_id on camera_B within time < min_travel_time from camera_A.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["re-id-anomaly","impossible-speed","tracking-fault","identity-clone"],
        trigger="re_id_time < min_physical_travel_time between_cameras",
        action="Investigate tracking system. Flag potential re-id spoofing.",
        risk_range=(55,75), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-026", name="Lighting Manipulation — Zone Darkened",
        description="Zone-specific illumination drop while other zones maintain normal lighting — "
                    "targeted light sabotage. "
                    "Requires: zone_brightness_delta > 60% AND adjacent zones normal "
                    "AND no maintenance.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["zone-darkness","light-sabotage","pre-crime","anomaly"],
        trigger="zone_brightness_drop>60% AND adjacent_zones_normal AND no_maintenance",
        action="Alert security. Restore lighting. Treat as pre-crime event.",
        risk_range=(65,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-027", name="Unusual Stationary-to-Mobile Ratio",
        description="Unusually high proportion of persons stationary versus historical baseline "
                    "— possible lockdown situation or crowd control event. "
                    "Requires: stationary_ratio > 80% AND person count > 3 AND sustained > 60 s.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["stationary-ratio","crowd","lockdown","anomaly","baseline"],
        trigger="stationary_ratio>80% AND count>3 AND sustained>60s",
        action="Staff walkthrough to assess cause.",
        risk_range=(35,55), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-028", name="Density Gradient Anomaly — Crowd Asymmetry",
        description="Crowd density significantly higher in one region than another without obvious cause — "
                    "possible blockage, attraction, or threat. "
                    "Requires: zone_A density > 3×zone_B AND both zones normally equal AND no event.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["density-gradient","asymmetry","crowd","anomaly","blockage"],
        trigger="zone_A_density>3×zone_B AND normally_equal AND no_event",
        action="Check for blockage or incident in low-density zone.",
        risk_range=(30,50), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-029", name="Noise-to-Motion Mismatch",
        description="High audio energy detected with low visual motion — possible verbal altercation, "
                    "phone threat, or concealed event. "
                    "Requires: audio_level > threshold AND scene_motion < low-threshold "
                    "AND duration > 10 s.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["audio-anomaly","noise","verbal-altercation","mismatch","anomaly"],
        trigger="audio_high AND motion_low AND sustained>10s",
        action="Staff walkthrough. Check for verbal altercation or distress.",
        risk_range=(32,52), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="ANO-030", name="Multi-Camera Coordination Anomaly",
        description="Suspicious pattern observed independently on 2+ cameras within short window — "
                    "multi-point threat or coordinated crime. "
                    "Requires: independent anomaly on ≥ 2 cameras AND temporal overlap < 60 s.",
        category=RuleCategory.ANOMALY, severity=Severity.CRITICAL,
        tags=["multi-camera","coordinated","multi-point","anomaly","threat"],
        trigger="anomaly on 2+cameras AND temporal_overlap<60s AND independent_triggers",
        action="Full security response. All cameras on alert. Call police.",
        risk_range=(82,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="ANO-031", name="Person Count Discrepancy",
        description="Manual headcount significantly different from system count — tracking fault "
                    "or concealed person. "
                    "Requires: system_count vs manual_count delta > 2 AND manually confirmed.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["count-discrepancy","tracking-fault","concealed-person","anomaly"],
        trigger="abs(system_count - manual_count) > 2",
        action="Physical sweep. Increase detection sensitivity.",
        risk_range=(55,75), cooldown_sec=180,
    ),
    BehavioralRule(
        rule_id="ANO-032", name="Weekend / Off-Pattern Activity in Business Hours",
        description="Activity pattern inconsistent with day of week — e.g. weekday crowd behaving "
                    "like weekend peak or vice versa. "
                    "Requires: footfall_pattern deviates > 50% from day-of-week model.",
        category=RuleCategory.ANOMALY, severity=Severity.LOW,
        tags=["off-pattern","baseline-deviation","business-intelligence","anomaly"],
        trigger="footfall_pattern_deviation>50% from day_of_week_model",
        action="Notify manager. Adjust staffing if needed.",
        risk_range=(8,25), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="ANO-033", name="Signal Interference — RFID / WiFi Anomaly",
        description="EAS/RFID system interference pattern detected — possible jammer in use. "
                    "Requires: EAS_false_positive_rate > 10× baseline AND no equipment malfunction.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["signal-interference","jammer","EAS","RFID","theft-enablement"],
        trigger="EAS_false_positive_rate>10×baseline AND no_equipment_fault",
        action="Alert security. Check for jamming device. Call police if confirmed.",
        risk_range=(68,85), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="ANO-034", name="Blank Frame / Feed Interruption",
        description="Camera feed goes blank or frozen during active monitoring period. "
                    "Requires: zero_motion_frames > 30 AND last_known_state had persons "
                    "AND not scheduled maintenance.",
        category=RuleCategory.ANOMALY, severity=Severity.CRITICAL,
        tags=["blank-frame","feed-interruption","camera-tampering","sabotage","blind"],
        trigger="zero_motion_frames>30 AND prior_persons_in_scene AND no_maintenance",
        action="Alert security. Check camera physically. Treat as blind-spot event.",
        risk_range=(82,97), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="ANO-035", name="High Alert Rate — Possible System Overload",
        description="Alert fire rate exceeds threshold — possible cascade or false-positive storm. "
                    "Requires: alert_rate > 10/min AND mixed severity AND no confirmed incident.",
        category=RuleCategory.ANOMALY, severity=Severity.MEDIUM,
        tags=["alert-overload","false-positive","system-health","cascade","anomaly"],
        trigger="alert_rate>10/min AND mixed_severity AND no_confirmed_incident",
        action="Review system. Increase temporal gate thresholds temporarily.",
        risk_range=(30,50), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="ANO-036", name="Unusual Object Trajectory",
        description="Object blob moving with non-human velocity or trajectory — thrown object, "
                    "projectile, or rolling item. "
                    "Requires: blob velocity > VEL_SPRINT AND aspect non-human AND "
                    "not vehicle context.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["projectile","thrown-object","trajectory","anomaly","threat"],
        trigger="blob_vel>VEL_SPRINT AND non_human_aspect AND not_vehicle",
        action="Alert security. Identify source. Check for injuries.",
        risk_range=(65,85), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="ANO-037", name="Repeated False Alarm — Calibration Needed",
        description="Same rule fires repeatedly with no confirmed incident — false positive pattern. "
                    "Requires: same rule_id fires > 5 times in 10 min AND no security confirmation.",
        category=RuleCategory.ANOMALY, severity=Severity.LOW,
        tags=["false-positive","calibration","rule-tuning","anomaly","system"],
        trigger="same_rule_fires>5 in 10min AND no_confirmation",
        action="Flag for rule threshold review. Temporarily suppress.",
        risk_range=(5,20), cooldown_sec=600,
    ),
    BehavioralRule(
        rule_id="ANO-038", name="Scene-Wide Motion Freeze",
        description="All tracked persons simultaneously stop moving — unnatural synchrony "
                    "suggesting threat instruction or system freeze. "
                    "Requires: all_tracks velocity < VEL_WALK×0.1 AND count > 2 AND sustained > 5 s.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["motion-freeze","synchronised","threat-instruction","anomaly","crowd"],
        trigger="all_track_vel<VEL_WALK×0.1 AND count>2 AND sustained>5s",
        action="Alert security. Possible active threat instruction ('nobody move').",
        risk_range=(70,88), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="ANO-039", name="Non-Human Blob — Animal on Premises",
        description="Blob with non-human shape/velocity ratio on premises — stray animal, "
                    "pest, or drone. "
                    "Requires: blob detected AND shape ≠ human AND velocity > 0 AND "
                    "indoor zone.",
        category=RuleCategory.ANOMALY, severity=Severity.LOW,
        tags=["animal","pest","drone","non-human","anomaly"],
        trigger="blob_shape!=human AND vel>0 AND indoor_zone",
        action="Staff to investigate. Remove animal safely.",
        risk_range=(5,20), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="ANO-040", name="Overnight Object Addition",
        description="Static object present in opening frame that was not present at closing — "
                    "item left overnight intentionally. "
                    "Requires: new_static_object in opening-frame AND not in closing-frame "
                    "AND not scheduled delivery.",
        category=RuleCategory.ANOMALY, severity=Severity.HIGH,
        tags=["overnight-object","concealed-device","IED","anomaly","opening-check"],
        trigger="new_static_object_at_open AND absent_at_close AND no_scheduled_delivery",
        action="Do NOT touch. Treat as suspicious package. Call police.",
        risk_range=(75,95), cooldown_sec=86400,
    ),
]


# ══════════════════════════════════════════════════════════
# BUSINESS INTELLIGENCE RULES  BIZ-001 → BIZ-030
# ══════════════════════════════════════════════════════════
BUSINESS_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="BIZ-001", name="Footfall Entry Event",
        description="New customer entered premises. Track crossed entry line with sufficient history.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["footfall","entry","traffic","analytics"],
        trigger="mature_track crosses entry_line downward",
        action="Log entry timestamp, zone, person ID for analytics.",
        risk_range=(0,10), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="BIZ-002", name="Exit Without Purchase",
        description="Customer exited without visiting checkout zone in session.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["no-purchase","exit","conversion","analytics"],
        trigger="person exits AND no_checkout_zone_dwell in session",
        action="Log for conversion analysis. Investigate if rate >40%.",
        risk_range=(5,20), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="BIZ-003", name="High Dwell Time — Product Interest",
        description="Customer stationary in product zone > 60 s — sales opportunity.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["dwell","product-interest","sales-opportunity","conversion"],
        trigger="IDLE/STANDING in product_zone AND dwell>60s",
        action="Dispatch nearby staff to assist.",
        risk_range=(8,18), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BIZ-004", name="Queue Length Exceeded Threshold",
        description="Checkout queue ≥ 3 persons — abandonment risk.",
        category=RuleCategory.BUSINESS, severity=Severity.MEDIUM,
        tags=["queue","checkout","wait-time","abandonment-risk"],
        trigger="3+persons in checkout_zone sustained 5s",
        action="Open additional checkout. Alert floor manager.",
        risk_range=(25,40), cooldown_sec=90,
    ),
    BehavioralRule(
        rule_id="BIZ-005", name="Peak Traffic Hour Detected",
        description="Entry rate exceeds peak threshold for this time of day.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["peak","traffic","staffing","capacity"],
        trigger="entry_rate > peak_threshold for time_of_day",
        action="Ensure adequate staffing. Review checkout and security coverage.",
        risk_range=(10,22), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-006", name="Returning Customer Recognised",
        description="Previously visited customer re-identified on entry.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["returning-customer","loyalty","re-id","personalisation"],
        trigger="re_id_match AND prior_visit AND no_alert_history",
        action="Personalised greeting opportunity. Log visit frequency.",
        risk_range=(0,12), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-007", name="Low Conversion Zone",
        description="High traffic zone with near-zero purchase events this hour.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["conversion","zone","placement","pricing","analytics"],
        trigger="zone_traffic>10 AND pickup_rate<5% in 1hr",
        action="Review product placement, signage, and pricing in this zone.",
        risk_range=(5,15), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-008", name="Staff Response Time Exceeded",
        description="Customer in high-interest zone > 5 min with no staff engagement.",
        category=RuleCategory.STAFF, severity=Severity.MEDIUM,
        tags=["staff","response-time","service-gap","missed-sale"],
        trigger="BIZ-003 active >5min AND no_staff_customer_proximity",
        action="Alert floor manager. Missed sales opportunity.",
        risk_range=(20,35), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-009", name="Group Shopping Detected",
        description="Three or more persons moving together as a group.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["group","family","basket-size","upsell"],
        trigger="3+persons coordinated_movement >2min",
        action="Opportunity for bundle/family deals. Ensure adequate stock.",
        risk_range=(0,10), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-010", name="Abandoned Basket / Cart",
        description="Shopping basket left unattended > 5 min with owner gone.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["abandoned-basket","cart","conversion","analytics"],
        trigger="cart_with_items AND stationary>300s AND owner>5m",
        action="Staff check: customer left or requires assistance?",
        risk_range=(8,20), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-011", name="Conversion Rate Drop Alert",
        description="Hourly conversion rate has dropped below minimum acceptable threshold.",
        category=RuleCategory.BUSINESS, severity=Severity.MEDIUM,
        tags=["conversion-rate","KPI","sales","analytics","alert"],
        trigger="hourly_conversion_rate < min_threshold AND footfall > 5",
        action="Alert manager. Review floor coverage and product availability.",
        risk_range=(22,40), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-012", name="Long Checkout Wait — Customer Abandonment",
        description="Single customer at checkout > 5 min without transaction completion.",
        category=RuleCategory.BUSINESS, severity=Severity.MEDIUM,
        tags=["checkout-wait","abandonment","service","KPI"],
        trigger="person in checkout_zone AND dwell>300s AND no_transaction_complete",
        action="Manager to assist. Check for payment issue or system problem.",
        risk_range=(25,42), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-013", name="Staff Coverage Gap — Zone Unattended",
        description="High-value merchandise zone has had no staff present for > 10 min.",
        category=RuleCategory.STAFF, severity=Severity.MEDIUM,
        tags=["staff-gap","zone-coverage","high-value","service"],
        trigger="high_value_zone AND no_staff_detected AND gap>600s",
        action="Alert floor manager to assign coverage.",
        risk_range=(22,42), cooldown_sec=600,
    ),
    BehavioralRule(
        rule_id="BIZ-014", name="High-Value Display Unmonitored",
        description="Jewellery or high-value display area without staff supervision for critical period.",
        category=RuleCategory.BUSINESS, severity=Severity.HIGH,
        tags=["high-value","unmonitored","jewellery","gold","security"],
        trigger="high_value_display_zone AND no_staff AND customer_present AND gap>300s",
        action="Immediate staff deployment to zone.",
        risk_range=(55,72), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-015", name="Shrinkage Pattern Detected",
        description="Stock-discrepancy pattern correlating with specific time window and zone.",
        category=RuleCategory.BUSINESS, severity=Severity.HIGH,
        tags=["shrinkage","loss-prevention","inventory","theft-pattern"],
        trigger="inventory_discrepancy AND correlated_zone AND correlated_time_window",
        action="Alert loss prevention. Review CCTV for correlated time window.",
        risk_range=(58,78), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-016", name="VIP Customer Identified",
        description="Known high-value customer re-identified on entry.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["VIP","high-value-customer","personalisation","loyalty"],
        trigger="re_id_match AND VIP_flag AND entry_event",
        action="Alert manager and senior staff for VIP service.",
        risk_range=(0,8), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-017", name="Product Hotspot — Unexpected Demand",
        description="Unusually high traffic around a specific product display today.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["hotspot","demand","product","analytics","restock"],
        trigger="zone_traffic>3×baseline AND product_zone AND no_promo",
        action="Alert merchandising. Check stock. Consider reorder.",
        risk_range=(5,18), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-018", name="Aisle Bottleneck — Flow Obstruction",
        description="Narrow aisle point creating traffic backup and customer frustration.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["bottleneck","aisle","flow","layout","customer-experience"],
        trigger="aisle_point AND velocity<VEL_WALK×0.3 AND 3+persons_queued",
        action="Staff to manage flow. Consider layout review.",
        risk_range=(8,22), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-019", name="Customer Complaint Posture Detected",
        description="Customer exhibiting raised-hands, pointing, or confrontational-but-non-violent "
                    "posture at staff — possible complaint.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["complaint","customer-service","posture","escalation"],
        trigger="customer_at_staff AND raised_arms AND not_assault_context AND sustained>10s",
        action="Alert supervisor to assist. Resolve complaint.",
        risk_range=(10,25), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BIZ-020", name="Employee Idle Time Excessive",
        description="Staff member stationary in non-checkout zone > 10 min during peak hours.",
        category=RuleCategory.STAFF, severity=Severity.LOW,
        tags=["staff-idle","productivity","peak-hours","management"],
        trigger="staff_id AND non_checkout_zone AND IDLE>600s AND peak_hours",
        action="Alert supervisor. Redirect staff to active zone.",
        risk_range=(5,18), cooldown_sec=600,
    ),
    BehavioralRule(
        rule_id="BIZ-021", name="Opening Preparation Incomplete",
        description="Store has opened without required staff in all key zones.",
        category=RuleCategory.STAFF, severity=Severity.MEDIUM,
        tags=["opening","preparation","compliance","staff-coverage"],
        trigger="opening_time AND required_zones_not_staffed AND customers_entering",
        action="Alert manager immediately. Deploy staff to unstaffed zones.",
        risk_range=(25,42), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-022", name="Closing Procedure Non-Compliance",
        description="Closing procedure not followed — customers still inside at lock-up time.",
        category=RuleCategory.STAFF, severity=Severity.HIGH,
        tags=["closing","compliance","security","procedure"],
        trigger="closing_time AND non_staff_still_inside AND no_manager_escort",
        action="Alert manager. Escort customers out. Do not lock in.",
        risk_range=(55,72), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-023", name="Delivery Verification Anomaly",
        description="Delivery received without verification against order — theft risk.",
        category=RuleCategory.BUSINESS, severity=Severity.MEDIUM,
        tags=["delivery","verification","stock","fraud","supply-chain"],
        trigger="delivery_event AND no_verification_scan AND stock_discrepancy",
        action="Hold delivery. Alert manager. Verify against order.",
        risk_range=(30,50), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-024", name="Peak Hour Staffing Insufficient",
        description="Current footfall-to-staff ratio below acceptable threshold during peak.",
        category=RuleCategory.STAFF, severity=Severity.MEDIUM,
        tags=["staffing","peak","ratio","service","KPI"],
        trigger="footfall_to_staff_ratio > threshold AND peak_hour",
        action="Call in additional staff. Alert manager.",
        risk_range=(22,40), cooldown_sec=1800,
    ),
    BehavioralRule(
        rule_id="BIZ-025", name="High-Value Zone Sales Opportunity",
        description="Multiple customers browsing high-value zone without staff approach.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["sales-opportunity","high-value","staff-dispatch","conversion"],
        trigger="2+customers in high_value_zone AND no_staff_approach AND dwell>60s",
        action="Dispatch senior sales staff immediately.",
        risk_range=(5,18), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="BIZ-026", name="Night Restocking Efficiency Alert",
        description="Night restocking activity not detected during scheduled window.",
        category=RuleCategory.STAFF, severity=Severity.LOW,
        tags=["restocking","night","efficiency","operations","compliance"],
        trigger="night_restock_window AND no_staff_activity AND shelves_flagged_low",
        action="Contact night supervisor. Check restocking schedule.",
        risk_range=(5,18), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-027", name="Customer Dwell Without Staff Engagement — 10 min",
        description="Customer interested in high-value product for > 10 min with no staff interaction.",
        category=RuleCategory.STAFF, severity=Severity.MEDIUM,
        tags=["missed-sale","engagement","high-value","dwell","staff"],
        trigger="high_value_zone AND dwell>600s AND no_staff_approach",
        action="Urgent staff dispatch. High-value sale risk.",
        risk_range=(28,45), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-028", name="Store Occupancy Near Maximum",
        description="Current occupancy approaching fire safety maximum.",
        category=RuleCategory.BUSINESS, severity=Severity.HIGH,
        tags=["occupancy","fire-safety","capacity","compliance"],
        trigger="current_occupancy > 0.85×max_capacity",
        action="Restrict entry. Alert manager and fire safety officer.",
        risk_range=(60,80), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="BIZ-029", name="Promotion Zone Underperforming",
        description="Active promotion zone has lower traffic than baseline despite signage.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["promotion","underperform","marketing","analytics","zone"],
        trigger="promo_zone AND traffic<baseline AND promo_active",
        action="Alert merchandising. Review signage and position.",
        risk_range=(5,15), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="BIZ-030", name="Repeat Purchase Behaviour Pattern",
        description="Customer visits same product zone on multiple consecutive days.",
        category=RuleCategory.BUSINESS, severity=Severity.LOW,
        tags=["repeat-purchase","loyalty","sales","analytics","returning"],
        trigger="re_id AND same_zone AND 3+consecutive_day_visits AND no_purchase",
        action="Staff engagement opportunity. Possibly undecided buyer.",
        risk_range=(2,12), cooldown_sec=86400,
    ),
]


# ══════════════════════════════════════════════════════════
# SYSTEM HEALTH RULES  SYS-001 → SYS-030
# Infrastructure, detection quality, and operational
# health monitoring rules.
# ══════════════════════════════════════════════════════════
SYSTEM_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="SYS-001", name="Camera Signal Loss",
        description="Camera feed has dropped — no frames received for > 5 s.",
        category=RuleCategory.SYSTEM, severity=Severity.CRITICAL,
        tags=["camera","signal-loss","offline","system-health"],
        trigger="no_frames_received > 5s AND camera_previously_live",
        action="Check camera power and network. Alert security to manual coverage.",
        risk_range=(80,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-002", name="Camera Image Quality Degraded",
        description="Frame analysis detects sustained blur, noise, or obstruction.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["image-quality","blur","obstruction","system-health","maintenance"],
        trigger="frame_sharpness < threshold AND sustained > 30s",
        action="Alert maintenance. Clean or replace camera.",
        risk_range=(60,80), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-003", name="Frame Rate Drop Detected",
        description="Effective FPS has dropped below minimum operational threshold.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["frame-rate","FPS","performance","system-health"],
        trigger="effective_fps < min_threshold AND sustained > 10s",
        action="Check CPU/GPU load. Reduce resolution or camera count if needed.",
        risk_range=(55,75), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-004", name="Detection Engine Exception",
        description="CV inference process raised an unhandled exception.",
        category=RuleCategory.SYSTEM, severity=Severity.CRITICAL,
        tags=["exception","crash","inference","system-health"],
        trigger="inference_exception AND not_handled",
        action="Check logs. Restart detection pipeline. Alert system admin.",
        risk_range=(80,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-005", name="High CPU / Memory Usage",
        description="System resources at critical level — detection may degrade.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["CPU","memory","resources","performance","system-health"],
        trigger="cpu_usage > 90% OR memory_usage > 85% sustained > 30s",
        action="Alert system admin. Consider reducing active camera count.",
        risk_range=(60,80), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-006", name="Disk Storage Warning",
        description="Recording storage below minimum safe threshold.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["storage","disk","recording","system-health"],
        trigger="disk_free < 10% AND recording_active",
        action="Alert system admin. Archive or delete oldest recordings.",
        risk_range=(60,80), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-007", name="Network Latency Alert",
        description="WebSocket or RTSP stream latency exceeding acceptable threshold.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["latency","network","RTSP","WebSocket","system-health"],
        trigger="stream_latency > 2000ms AND sustained > 30s",
        action="Check network infrastructure. Alert IT.",
        risk_range=(35,55), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-008", name="WebSocket Client Disconnect",
        description="Active monitoring client has disconnected from WebSocket feed.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["WebSocket","disconnect","monitoring","system-health"],
        trigger="ws_client_disconnect AND ws_client_count drops to 0",
        action="Alert operator. Reconnect monitoring client.",
        risk_range=(30,50), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-009", name="Camera Orientation Changed",
        description="Camera field of view has shifted — possible tampering or movement.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["camera-orientation","tampering","calibration","system-health"],
        trigger="scene_shift > threshold AND persistent AND no_PTZ_command",
        action="Recalibrate zones. Alert security of possible tampering.",
        risk_range=(62,82), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-010", name="Background Model Drift",
        description="MOG2 background model has drifted from baseline — detection accuracy degraded.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["background-model","MOG2","drift","detection","system-health"],
        trigger="background_confidence < threshold AND false_positive_rate_spike",
        action="Reinitialise background model. Allow warmup period.",
        risk_range=(30,50), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-011", name="Track ID Explosion",
        description="Number of concurrent active tracks far exceeds expected maximum.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["track-explosion","tracking","performance","false-detection"],
        trigger="active_track_count > 3×expected_maximum",
        action="Reset tracking. Check for background noise or lighting issue.",
        risk_range=(28,48), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-012", name="Alert Queue Overflow",
        description="Alert broadcast queue has exceeded buffer — alerts may be dropped.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["alert-queue","overflow","broadcast","system-health"],
        trigger="alert_queue_depth > max_buffer",
        action="Alert system admin. Increase rate limiting. Reduce sources.",
        risk_range=(55,75), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-013", name="RTSP Stream Reconnect Event",
        description="RTSP stream required reconnect after drop.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["RTSP","reconnect","stream-drop","system-health"],
        trigger="RTSP_reconnect_event AND backoff_triggered",
        action="Log event. If frequent (>3/hour), check network and camera config.",
        risk_range=(25,45), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-014", name="Video File End — Loop Reset",
        description="Uploaded video file reached end and looped — tracking state reset.",
        category=RuleCategory.SYSTEM, severity=Severity.LOW,
        tags=["video-loop","file-end","tracking-reset","system-health"],
        trigger="file_source AND end_of_file AND loop_triggered",
        action="Informational. Tracks cleared for fresh analysis.",
        risk_range=(0,10), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SYS-015", name="Detection Confidence Consistently Low",
        description="Average detection confidence has been below threshold for extended period.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["confidence","detection","accuracy","degraded","system-health"],
        trigger="avg_detection_confidence < 0.5 AND sustained > 120s",
        action="Check lighting, camera cleanliness, and model state.",
        risk_range=(55,72), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-016", name="Night Mode Transition",
        description="System has transitioned to night-time detection mode.",
        category=RuleCategory.SYSTEM, severity=Severity.LOW,
        tags=["night-mode","lighting","transition","system-health"],
        trigger="frame_brightness < night_threshold AND time_of_day matches",
        action="Informational. Verify IR/night cameras are operational.",
        risk_range=(0,10), cooldown_sec=3600,
    ),
    BehavioralRule(
        rule_id="SYS-017", name="Frame Too Dark — Detection Impaired",
        description="Scene illumination too low for reliable detection.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["dark","illumination","detection-impaired","system-health"],
        trigger="frame_mean_brightness < 20 AND sustained > 10s AND not_night_mode",
        action="Alert facilities to restore lighting. Alert security of blind period.",
        risk_range=(60,80), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-018", name="Recording Storage Full — Stop Recording",
        description="Storage completely full — recording has stopped.",
        category=RuleCategory.SYSTEM, severity=Severity.CRITICAL,
        tags=["storage-full","recording-stopped","system-health","evidence"],
        trigger="disk_free == 0 AND recording_stopped",
        action="URGENT: Free storage immediately. Evidence collection at risk.",
        risk_range=(85,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-019", name="Camera Auth Failure — RTSP 401",
        description="RTSP camera stream returning authentication failure.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["auth-failure","RTSP","credentials","system-health"],
        trigger="RTSP_status == 401 AND repeated_failure",
        action="Check and update camera credentials. Alert IT.",
        risk_range=(55,72), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-020", name="False Positive Rate Spike",
        description="System firing significantly more alerts than confirmed incidents.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["false-positive","accuracy","system-health","calibration"],
        trigger="alert_confirmation_rate < 10% AND alert_count > 10 in 10min",
        action="Review temporal gate thresholds. Check camera alignment.",
        risk_range=(25,45), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-021", name="Analytics Data Gap",
        description="Analytics snapshot not received within expected interval.",
        category=RuleCategory.SYSTEM, severity=Severity.LOW,
        tags=["analytics","data-gap","system-health","monitoring"],
        trigger="analytics_snapshot_interval > 2×expected_interval",
        action="Check analytics pipeline. Alert system admin.",
        risk_range=(10,25), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-022", name="Rule Engine Exception",
        description="Behavioural rule evaluation raised an unhandled exception.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["rule-engine","exception","system-health","crash"],
        trigger="rule_evaluation_exception AND not_caught",
        action="Log full traceback. Alert system admin. Restart if persistent.",
        risk_range=(60,80), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-023", name="Optical Flow Failure",
        description="Lucas-Kanade optical flow calculation failing — velocity refinement degraded.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["optical-flow","velocity","system-health","tracking"],
        trigger="optical_flow_exception AND repeated > 5 in 30s",
        action="Check frame resolution and quality. May fall back to centroid velocity.",
        risk_range=(25,45), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-024", name="Broadcast Failure — Alert Not Delivered",
        description="WebSocket broadcast failed for one or more alerts.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["broadcast","WebSocket","delivery-failure","system-health"],
        trigger="broadcast_exception AND alert_dropped",
        action="Check WebSocket connections. Reconnect clients.",
        risk_range=(55,72), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="SYS-025", name="Warmup Period Active — Alerts Suppressed",
        description="Background model still in warmup phase — rules not yet firing.",
        category=RuleCategory.SYSTEM, severity=Severity.LOW,
        tags=["warmup","MOG2","startup","system-health"],
        trigger="frame_count < WARMUP_FRAMES AND camera_just_started",
        action="Informational. System will begin alerting after warmup completes.",
        risk_range=(0,5), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="SYS-026", name="High Alert Volume — Rate Limiter Active",
        description="Camera-level rate limiter is suppressing alerts due to excessive volume.",
        category=RuleCategory.SYSTEM, severity=Severity.MEDIUM,
        tags=["rate-limit","suppression","system-health","alert-volume"],
        trigger="rate_limiter_triggered AND alerts_suppressed > 3 in 60s",
        action="Review scene for genuine incident vs false positive storm.",
        risk_range=(20,40), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-027", name="Webcam Device Not Found",
        description="Local webcam device could not be opened.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["webcam","device","system-health","hardware"],
        trigger="webcam_open_failed AND source=WEBCAM",
        action="Check webcam connection. Try different device_id.",
        risk_range=(60,80), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-028", name="Upload File Corrupt / Unreadable",
        description="Uploaded video file cannot be read by OpenCV.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["file-corrupt","upload","video","system-health"],
        trigger="file_source AND cap_open_failed AND file_exists",
        action="Re-upload file. Check codec and format compatibility.",
        risk_range=(55,72), cooldown_sec=300,
    ),
    BehavioralRule(
        rule_id="SYS-029", name="GPU Thermal Throttling",
        description="GPU temperature causing inference throttling — detection latency increasing.",
        category=RuleCategory.SYSTEM, severity=Severity.HIGH,
        tags=["GPU","thermal","throttle","performance","system-health"],
        trigger="gpu_temp > 85C AND inference_time > 2×baseline",
        action="Alert system admin. Improve cooling. Reduce workload.",
        risk_range=(55,75), cooldown_sec=120,
    ),
    BehavioralRule(
        rule_id="SYS-030", name="System Restart Required",
        description="Multiple system health alerts have fired in short window — system unstable.",
        category=RuleCategory.SYSTEM, severity=Severity.CRITICAL,
        tags=["restart","unstable","cascade-failure","system-health"],
        trigger="3+SYS_alerts in 5min AND different_rules",
        action="Alert system admin. Plan controlled restart during low-risk window.",
        risk_range=(75,95), cooldown_sec=600,
    ),
]


# ══════════════════════════════════════════════════════════
# CROWD SAFETY RULES  CRW-001 → CRW-004
# (kept for backward compatibility with manager.py)
# ══════════════════════════════════════════════════════════
CROWD_RULES: List[BehavioralRule] = [

    BehavioralRule(
        rule_id="CRW-001", name="Crowd Density Critical",
        description="Area density exceeds safe occupancy limit. "
                    "Requires: ≥ 5 persons in frame AND sustained ≥ 3 s.",
        category=RuleCategory.CROWD, severity=Severity.CRITICAL,
        tags=["crowd","density","fire-safety","occupancy"],
        trigger="5+persons in frame sustained 3s",
        action="Restrict entry immediately. Notify fire safety officer.",
        risk_range=(85,99), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRW-002", name="Crowd Surge / Stampede Risk",
        description="Rapid crowd velocity increase toward single exit — panic.",
        category=RuleCategory.CROWD, severity=Severity.CRITICAL,
        tags=["surge","stampede","panic","evacuation"],
        trigger="avg_crowd_vel>1.8m/s toward_single_exit within 10s",
        action="Activate emergency protocol. Open all exits. PA announcement.",
        risk_range=(90,99), cooldown_sec=30,
    ),
    BehavioralRule(
        rule_id="CRW-003", name="Unattended Child Detected",
        description="Child alone > 3 minutes without accompanying adult.",
        category=RuleCategory.CROWD, severity=Severity.HIGH,
        tags=["child","unattended","safeguarding","welfare"],
        trigger="small_stature alone > 180s",
        action="Send staff immediately. Follow lost-child protocol.",
        risk_range=(70,88), cooldown_sec=60,
    ),
    BehavioralRule(
        rule_id="CRW-004", name="Person on Ground / Fall Detected",
        description="Person horizontal and stationary — possible fall or assault victim. "
                    "Requires: AR > 2.4 AND vel < VEL_RUN×0.4 AND state=FALLEN AND dwell ≥ 2 s.",
        category=RuleCategory.CROWD, severity=Severity.CRITICAL,
        tags=["fall","medical","emergency","down","FALLEN"],
        trigger="state=FALLEN AND AR>2.4 AND vel<VEL_RUN×0.4 AND dwell≥2s",
        action="Send first-aid immediately. Call ambulance if unresponsive.",
        risk_range=(88,99), cooldown_sec=45,
    ),
]


# ══════════════════════════════════════════════════════════
# MASTER RULE LIST
# ══════════════════════════════════════════════════════════
ALL_RULES: List[BehavioralRule] = (
    CRIME_RULES     +   # CRM-001..060  (60 rules)
    SECURITY_RULES  +   # SEC-001..060  (60 rules)
    BEHAVIOR_RULES  +   # BEH-001..040  (40 rules)
    ANOMALY_RULES   +   # ANO-001..040  (40 rules)
    BUSINESS_RULES  +   # BIZ-001..030  (30 rules)
    SYSTEM_RULES    +   # SYS-001..030  (30 rules)
    CROWD_RULES         # CRW-001..004  ( 4 rules — backward compat)
)

RULES_BY_ID: dict = {r.rule_id: r for r in ALL_RULES}


def get_rule(rule_id: str):
    return RULES_BY_ID.get(rule_id)


def get_rules_by_category(category: RuleCategory) -> List[BehavioralRule]:
    return [r for r in ALL_RULES if r.category == category]


def get_rules_by_severity(severity: Severity) -> List[BehavioralRule]:
    return [r for r in ALL_RULES if r.severity == severity]

