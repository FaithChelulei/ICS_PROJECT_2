# Model evaluation: person-level split, validation limits, synthetic attacks

Script: `ml/scripts/12_validated_evaluation.py`. Results:
`ml/models/validated_results.json`, log `ml/results/12_validated_evaluation.txt`.
The models the website uses (`ml/models/*.joblib`, `*.keras`) were not
changed. This is a second, stricter evaluation of the same method.

## Why a second evaluation

The original evaluation (`02_train_models.py`) has three weaknesses:

1. **Split by session.** The same person's sessions could be in both
   training and test, so the model was partly tested on people it knew.
2. **Limit chosen on the test set.** The best-F1 limit was picked on the test
   set and reported on the same set, which flatters precision and recall.
3. **Too few auditor attacks.** The Security Auditor role has 7 attack
   sessions, all from one person (JRG0207).

## Method

For each role, separately:

- **People, not sessions, are split.** 60% of the people with no attacks
  train the models; 20% form a validation set and 20% a test set. People who
  carried out an attack are divided between validation and test and are never
  used for training. No person is in two sets.
- **Same models as the website:** Isolation Forest (200 trees) and
  Autoencoder (7-12-6-12-7), trained on the training people's sessions,
  scores averaged.
- **The limit (best F1) is chosen on validation** and reported once on test.
- **Synthetic attacks.** A normal session of a held-out person is given the
  attack signature of a *real* CERT attack session from another role:

  | CERT scenario | Features copied from the real attack |
  |---|---|
  | 1. Works after hours, takes data before leaving | after hours, session length, files |
  | 2. Job hunting, steals data gradually | files, activity that day, session length |
  | 3. Uses other people's computers | own PC, computers used that day, activity that day, after hours |

  100 per scenario in validation and 100 in test, built from different
  people and different donor attackers. For the Security Auditor, whose only
  real attacker falls in the test set, the limit is chosen on the synthetic
  validation attacks. Synthetic results are reported separately from real
  CERT results, and only AUC, recall and false-alarm rate are given for them:
  their precision depends on how many attacks were injected, so it means
  nothing.
- **Five repeats** with different random groupings of people (seeds 42, 1,
  2, 3, 4). Figures are the mean, with the range in brackets.
- **Baselines** on the same test people: a one-line rule, each model
  alone, and the deployed combination (see below).

## Results on real CERT attacks (test set, unseen people)

| Role | Measure | Original | Validated (mean, range over 5 runs) |
|---|---|---|---|
| Caregiver | AUC | 0.769 | **0.760** (0.744 to 0.770) |
| | Recall | 60.8% | 66.3% (61.0 to 77.9) |
| | Precision | 5.2% | 2.5% (1.7 to 2.9) |
| | False-alarm rate | 20.4% | 24.2% (21.4 to 31.5) |
| Security Auditor | AUC | 0.665 | 0.666 (0.514 to 0.804) |
| | Recall (7 attacks) | 42.9% | 25.7% (0 to 42.9) |
| SysAdmin | AUC | 0.719 | **0.618** (0.521 to 0.764) |
| | Recall | 31.7% | 18.5% (0.4 to 32.0) |
| | False-alarm rate | 12.1% | 13.8% (0 to 35.0) |

## Results on synthetic attacks (test set, unseen people)

| Role | AUC | Recall at validated limit | False-alarm rate |
|---|---|---|---|
| Caregiver | 0.857 (0.736 to 0.935) | 83.4% | 24.2% |
| Security Auditor | **0.873** (0.827 to 0.940) | 50.2% | 8.8% |
| SysAdmin | 0.846 (0.774 to 0.909) | 59.3% | 13.8% |

Recall by scenario, Security Auditor (mean of 5 runs): scenario 1 27%,
scenario 2 25%, scenario 3 (other people's computers) 98%.

## What this shows

1. **Caregiver: the result holds.** AUC stays at 0.76 on people the model
   never saw, so it ranks unusual sessions as well for new people as for
   known ones. Precision halves (5.2% to 2.5%) mainly because attacks are a
   smaller share of this test set (about 0.9% instead of 1.8%); precision
   always falls when attacks are rarer.
2. **SysAdmin: the original figure was optimistic.** AUC falls from 0.719 to
   0.618 on unseen administrators. With only 40 administrators, the model
   trains on about 17 people and partly learned individual habits. The
   honest SysAdmin figure is about 0.62, varying with which people are held
   out.
3. **Security Auditor: the real result is unstable, as expected.** With
   one attacker, AUC ranges from 0.51 to 0.80 depending on which colleagues
   are in the test set. On 300 synthetic attacks built from real CERT attack
   behaviour, the auditor model reaches AUC 0.87: it separates
   attack-like behaviour well, catching almost every use of other people's
   computers (scenario 3) but only about a quarter of the subtle scenario 1
   and 2 attacks.
4. **Subtle CERT attacks are hard for every role.** Scenarios 1 and 2 change
   only a few session measurements, so they overlap with normal work. Precision
   stays low (2% to 8%), which is why a flag triggers a reversible check plus
   human review and never an automatic penalty.

## Baselines: what the machine learning adds

On the same unseen test people, the deployed combination is compared with
each model alone and with a one-line rule: **after hours, or more files
than 95% of that person's own sessions**. Threshold-free measures, mean
over the 5 splits (range in brackets):

- **ROC-AUC**: how well attacks are ranked above normal sessions (0.5 is
  guessing).
- **PR-AUC** (average precision): the honest measure when attacks are
  rare. Guessing scores the share of attacks in the test set.
- **Recall at 1% false alarms**: the share of attacks caught when only 1
  normal session in 100 is flagged.

### Real CERT attacks

| Role (share of attacks) | Detector | ROC-AUC | PR-AUC | Recall at 1% false alarms |
|---|---|---|---|---|
| Caregiver (0.91%) | Rule | 0.547 (0.542 to 0.556) | 0.015 | 0.4% |
| | Isolation Forest | 0.760 (0.744 to 0.770) | 0.018 | 0.6% |
| | Autoencoder | 0.712 (0.628 to 0.756) | 0.018 | **3.1%** |
| | **Combined (deployed)** | **0.760** (0.744 to 0.770) | **0.019** | 0.7% |
| Security Auditor (0.33%, one attacker) | Rule | 0.636 (0.633 to 0.642) | 0.044 | 5.7% |
| | Isolation Forest | 0.658 (0.520 to 0.802) | 0.064 | 11.4% |
| | Autoencoder | **0.700** (0.571 to 0.809) | 0.050 | 11.4% |
| | **Combined (deployed)** | 0.666 (0.514 to 0.804) | **0.068** | **14.3%** |
| SysAdmin (0.96%) | Rule | 0.424 (0.366 to 0.465) | 0.009 | 0.9% |
| | Isolation Forest | 0.597 (0.509 to 0.763) | 0.018 | 0.6% |
| | Autoencoder | 0.528 (0.476 to 0.653) | 0.024 | **4.2%** |
| | **Combined (deployed)** | **0.618** (0.521 to 0.764) | **0.026** | 3.5% |

### Synthetic attacks (built from real CERT attack sessions)

| Role | Detector | ROC-AUC | PR-AUC | Recall at 1% false alarms |
|---|---|---|---|---|
| Caregiver | Rule | 0.618 | 0.012 | 0.4% |
| | Isolation Forest | 0.857 | 0.047 | 23.4% |
| | Autoencoder | 0.847 | **0.198** | **43.8%** |
| | **Combined (deployed)** | **0.857** | 0.128 | 24.8% |
| Security Auditor | Rule | 0.661 | 0.346 | 6.9% |
| | Isolation Forest | 0.869 | 0.580 | 31.5% |
| | Autoencoder | 0.860 | 0.632 | **42.9%** |
| | **Combined (deployed)** | **0.873** | **0.642** | **42.9%** |
| SysAdmin | Rule | 0.538 | 0.044 | 10.2% |
| | Isolation Forest | 0.721 | 0.042 | 1.9% |
| | Autoencoder | **0.853** | **0.539** | **50.1%** |
| | **Combined (deployed)** | 0.846 | 0.358 | 38.9% |

### What the baselines show

1. **The models add a lot over a simple rule in ranking.** For caregivers
   ROC-AUC rises from 0.547 to 0.760; for administrators the rule is worse
   than guessing (0.424) and the combined model reaches 0.618. On
   synthetic attacks every model beats the rule by 0.2 or more.
2. **On real CERT attacks every detector has low precision.** Caregiver
   PR-AUC is 0.019 against 0.009 for guessing: about twice as good as
   chance, still low in absolute terms. CERT insiders change only a few
   session measurements. This is why a flag starts a reversible check and
   human review, never an automatic penalty.
3. **The two models do different jobs.** The Isolation Forest gives the
   ranking (for caregivers the combined ROC-AUC equals its own), while the
   autoencoder catches more at a low false-alarm rate (3.1% against 0.6%
   for caregivers at 1% false alarms) and is the strongest single model on
   synthetic attacks. Averaging keeps the Isolation Forest's ranking and
   gains part of the autoencoder's precision; it is best or level-best on
   ROC-AUC in four of six comparisons, but it does not always beat the
   autoencoder on PR-AUC.
4. **What would improve it:** the autoencoder's share of the score is small
   because its training maximum is an outlier (min-max scaling). Scaling
   both scores by percentile instead, so neither dominates, is the obvious
   next step; it would change every live score and limit, so it is left as
   future work rather than changed before the defence.

## The live limits on this data

At the website's limits (0.40, 0.65, 0.60) recall on real CERT attacks is
close to zero (Caregiver 0.4% to 0.7%; SysAdmin 0.4% to 11%), with false
alarms under 1% for Caregiver. On synthetic attacks it is 11% to 25%
(Caregiver), 20% to 41% (Security Auditor) and 21% to 56% (SysAdmin). This
confirms what `docs/RISK_THRESHOLDS.md` already states: the live limits are
calibrated to stop routine work being signed out and to catch the strong
patterns of this app (night-time use, bursts, mass access, a new device),
not the subtle CERT insiders. A real deployment would retrain on the
organisation's own logs.

## Limits of this evaluation

- Synthetic attacks follow patterns chosen by us. They show that the models
  detect these known patterns, not that they would detect any real attacker.
- The Security Auditor and SysAdmin roles have few people (20 and 40), so
  every figure for them varies with the split.
- The models are retrained for each run; the website's models were trained
  once by `02_train_models.py` and are not replaced.
