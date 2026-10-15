# Voice notes in a disguised voice

Owner request (2026-10-15): *"add a voice note feature but with a security
mind twist — can we morph voice notes advanced enough where AI detection
cannot identify or link a voice note to a specific user in real life?
Similar to how the Professor in Money Heist morphs his voice."*

## The short answer

No voice changer can **guarantee** that. A voice note can be made much
harder to recognise or link by voice, and that is what this does. It is
measured below against a real speaker-recognition network. Nothing here
changes **what** is said: your words, phrasing, accent and any background
event in the note can still identify you. Where it really matters, type.

The early-2000s voice-changer plugins, and the box the Professor holds to
the phone, move pitch (sometimes formants) by one fixed amount. A fixed,
known transform can be inverted. A recogniser trained on shifted speech
also recognises the speaker through it. Pitch is not mainly what
identifies a voice.

## What happens to a note

```
microphone ─► memory ─► voice mask (Rust) ─► Ogg Opus / WAV ─► encrypted file transfer
```

* **The real recording never touches disk.** It is held in memory in the
  Python engine, never in Kotlin. It is overwritten as soon as the mask has
  run, or as soon as the note is cancelled, the app closes or Wipe & Exit
  runs.
* **The mask** (`Rust/src/voice_mask.rs`) runs on the device:
  1. resample to 16 kHz (nothing above 8 kHz survives);
  2. measure and remove the recording's long-term spectral tilt (the
     microphone, the room, the distance), then apply a fixed tilt;
  3. a noise gate, so room tone between words goes;
  4. source/filter split (20th-order LPC, 30 ms frames);
  5. **vocal tract**: every formant moved by a McAdams warp (the
     VoicePrivacy Challenge baseline B2) *and* a linear vocal-tract-length
     change, plus slightly broader formants;
  6. **voice source**: pitch moved (down 16–30 % or up 20–45 %) and
     speaking rate changed (±10 %) with WSOLA;
  7. **Synthetic** mode discards the speaker's source entirely and drives
     the warped vocal tract with a generated monotone pulse train, so no
     glottal pulse shape, breathiness, jitter or intonation of yours
     remains. It sounds like a vocoder;
  8. loudness normalised.
* **Every note gets new, secret settings**, drawn from the OS random
  generator inside the Rust function. They are never returned, logged or
  stored. So there is no single transform to undo, and two notes by the
  same person do not share a disguised voice either.
* **Fail closed.** If the mask is missing from a build, a disguised note is
  refused. It is never quietly sent in your own voice. "My voice"
  (`natural`) is a separate, explicit choice.
* **The file holds only audio**: Ogg Opus with a fixed vendor string and no
  tags, or a bare WAV where the build has no Opus encoder. It has a random
  name. It is sent as an ordinary file, so the session and SMP verification
  gates, the Rust sealing and the receiver's accept prompt all apply. You
  hear exactly the disguised file before you send it.

## Measured

`tools/voice_mask_eval.py` uses Resemblyzer (a GE2E speaker encoder) on the
Free Spoken Digit Dataset: 6 real speakers, 14 notes each of 8 spoken
digits. Results are averaged over 3 runs, each with fresh mask settings.
The equal error rate (EER) is the recogniser's error at its best
threshold: **50 % = coin toss, 0 % = perfect**.

| mode | attacker who knows your real voice | linking two notes by voice | digit recognition (pocketsphinx) |
|---|---|---|---|
| My voice | 0 % | 0 % | 71 % |
| Disguised | 34 % | 39 % | 44 % |
| Synthetic | 42 % | 47 % | 44 % |

How to read it:

* Undisguised, the network recognises every speaker every time.
* Synthetic takes it close to guessing in both attacks. Disguised keeps more
  of your timing and expression, and with it more of your identity.
* The intelligibility column comes from an old, voice-sensitive recogniser
  used as a rough proxy. People cope with shifted voices far better than
  pocketsphinx does, but the drop is real: the disguise costs some clarity.
  The settings were chosen as a balance between the two columns. Stronger
  settings hid more and were understood less.
* **Not measured, and stronger than both attackers above:** an adversary
  who trains a recogniser on speech put through this same mask. Expect them
  to do better than these numbers. The randomness per note is what limits
  them.
* The corpus is small and 8 kHz. Treat the numbers as indicative.

## Where it is

* **Synthetic is the default** (owner's choice after listening, 2026-10-15):
  all three were easy to understand, and Synthetic is the one the
  recogniser matches least.
* Android: in a conversation, **Voice note** (next to *Send a file*).
  Choose Synthetic / Disguised / My voice, then Record → Stop → Play →
  Send or Discard. A received note opens in the in-app player like any
  audio file.
* Desktop: the microphone button in the conversation header; received
  notes get **Play**.
* Terminal: `/voice [synthetic|disguise|natural]` (synthetic if omitted), then `/voice` to stop,
  then `/voice play`, `/voice send` or `/voice cancel`.
* Groups: the same, to a secure group, over MLS.
