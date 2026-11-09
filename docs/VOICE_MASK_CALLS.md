# Voice masking in calls

A **Mask my voice** button on every call (1:1 and group; Android, desktop,
terminal `/mask`). On, the people you call hear a different-sounding voice
saying your words, clearly. It is remembered between calls.

## What it does

Everything happens on your own device, before the audio is encoded and
encrypted, so your real voice never leaves it.
(`Rust/src/live_mask.rs`, called from `otrv4plus_audio.LiveMasker`.)

- **Pitch and formants move together.** The pitch goes 4.5-6.5 semitones and
  the formants (the resonances of the throat and mouth) 12-20 % in the same
  direction. Moving both is what makes a low voice sound like a high one, not
  like a sped-up tape, and it keeps vowels and consonants clear.
- **Low voices go up, high voices go down.** In the first moment of speech it
  measures your pitch, roughly men to a female range and women to a male
  range. You are silent for that moment (about a third of a second of
  speech) and never sent unmasked. The answer (one bit) is kept in memory
  for the app's next call, never on disk.
- **A new disguise every call.** The amounts are drawn at random when a call
  starts and are never sent, logged or stored. Two calls of yours do not
  sound like the same disguised voice. In a group call every phone masks
  only its own voice, so five people are five independent masks.
- **The top of the spectrum is cut.** Nothing above 7.5 kHz is sent. Much
  of a microphone's and a voice's fine detail lives there; intelligibility
  does not need it.
- **Delay and cost.** It adds 32 ms of delay. On a laptop it uses about 2 %
  of one core.
- **It fails closed.** If masking cannot run, the call carries silence, not
  your voice.

Voice notes keep their own, stronger masker: a fully synthetic voice
(`docs/VOICE_NOTES.md`). It was not used for calls because live speech must
stay easy to follow.

## What it does not do

- It stops people recognising you by ear, and it defeats matching against
  recordings of your normal voice.
- It does **not** stop a determined analyst who trains speaker recognition
  on masked speech. Rhythm, intonation and accent survive a pitch-and-formant
  change. Published evaluations of signal-processing masking (the
  VoicePrivacy Challenge baselines) show this.
- **What you say is untouched.** Words, names, phrasing, dialect and
  background sounds can identify you whatever you sound like.
- The other people in the call are not told you are masked.
