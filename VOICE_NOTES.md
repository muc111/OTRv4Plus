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
  2. a high-pass filter and a noise gate, so room tone between words goes;
  3. a short-time spectrum (32 ms frames, 8 ms apart). Each frame's
     **envelope** (the vocal tract) is a smooth, cepstrally liftered outline
     of the spectrum;
  4. **vocal tract**: the envelope is moved along frequency twice: a
     McAdams warp (the VoicePrivacy Challenge baseline B2) and a bilinear
     vocal-tract-length warp, both random. Every formant moves, by a
     different amount;
  5. **voice source**: in **Disguised**, your harmonics, pitch-shifted
     (down 14–26 % or up 18–38 %), under the warped envelope; in
     **Synthetic**, a generated source instead (a monotone pulse train with
     a little jitter, breath above ~3 kHz, noise where you were unvoiced),
     so no glottal pulse shape, breathiness or intonation of yours remains;
  6. a **fixed reference balance**: the note's long-term spectrum is pulled
     to the standard long-term speech spectrum, so neither brightness, the
     microphone nor your own spectral colour is a cue;
  7. speaking rate changed (±8 %) with WSOLA, and loudness normalised.

  **Changed in rc.77** (device report: *"disguise and synthetic sound like a
  whistle"*). Until rc.76 step 3–4 warped the poles of an LPC filter. With
  some of the random settings that pushed resonances towards 8 kHz with
  almost no damping, and each 30 ms frame was filtered from scratch, so
  they rang. On the reference clip Synthetic put 80 % of its energy above
  4 kHz (speech: about 12 %); through a phone microphone and room, Disguise
  did it too. The envelope warp cannot ring: it never builds a resonator.
  A Rust test (`no_whistle`) now fails any setting that puts more than a
  quarter of the energy above 4 kHz, or concentrates the 3–8 kHz energy in
  a few lines. **My voice** (`natural`) is unchanged.
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
| My voice | 0 % | 0 % | 72 % |
| Disguised | 31 % | 32 % | 37 % |
| Synthetic | 41 % | 37 % | 46 % |

Measured for rc.77, on the new spectral mask (3 runs, 200 digits). For
comparison, rc.66–rc.76 (the LPC mask that whistled on phones): Disguised
34 % / 39 % / 44 %, Synthetic 42 % / 47 % / 44 %. **The trade, said
plainly:** against an attacker who knows your real voice, Synthetic is as
strong as before; linking two of your notes to each other became somewhat
easier (part of the old figure came from the random distortion -- the
whistle -- itself). Settings tried and rejected, by measurement: a bilinear
warp alone (25–27 %), a McAdams warp alone (24–35 %, but the clearest), a
smoother envelope or larger warps (as strong, but word recognition halved),
a random spectral ripple, and a warp that drifts within the note (no
gain).

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
