from enum import Enum


class FirewallDecision(str, Enum):
  ALLOW = "allow"
  BLOCK = "block"
  WHITELIST = "whitelist"
  BLACKLIST = "blacklist"
  TEMPORARY_BLOCK = "temporary_block"
  NO_MATCH = "no_match"


class AutomaticRuleTrigger(str, Enum):
  THREAT_DETECTED = "threat_detected"
  LOW_TRUST_SCORE = "low_trust_score"
  ATTACK_PATTERN = "attack_pattern"
  COUNTRY_BLOCK = "country_block"
  POLICY_VIOLATION = "policy_violation"


class AutomaticRuleAction(str, Enum):
  BLOCK = "block"
  BLACKLIST = "blacklist"
  TEMPORARY_BLOCK = "temporary_block"
