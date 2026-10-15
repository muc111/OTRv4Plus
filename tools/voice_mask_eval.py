# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Measure the voice mask against a pretrained speaker-recognition network.

NOT part of the app or the test suite: it needs PyTorch and Resemblyzer
(a GE2E speaker encoder) and a speech corpus, none of which ship.

    python -m venv evalenv
    evalenv/bin/pip install torch resemblyzer soundfile <otrv4_core wheel>
    # the Free Spoken Digit Dataset, recordings/{digit}_{speaker}_{n}.wav:
    #   https://github.com/Jakobovski/free-spoken-digit-dataset
    evalenv/bin/python tools/voice_mask_eval.py path/to/recordings

THE ATTACKERS (VoicePrivacy Challenge terms)
--------------------------------------------
  ignorant   knows the speaker's real voice (enrolment on unmasked notes) and
             is given a masked note: "is this them?"
  linking    has only masked notes and asks whether two of them are by the
             same person: the "link my notes together" attack.

The number is the equal error rate (EER): 50 % is a coin toss (nothing
learnt), 0 % is perfect recognition. An attacker who trains a model on
masked speech of known speakers will do better than both of these; that is
not measured here and the documentation says so.
"""
from __future__ import annotations

import os
import random
import sys
import wave
from collections import defaultdict

import numpy as np

import otrv4_core

DIGITS_PER_NOTE = 8
NOTES_PER_SPEAKER = 14
ENROL = 3


def read(path):
    with wave.open(path, "rb") as w:
        return w.readframes(w.getnframes()), w.getframerate()


def notes(directory, rng):
    by = defaultdict(list)
    for name in sorted(os.listdir(directory)):
        if name.endswith(".wav"):
            by[name.split("_")[1]].append(os.path.join(directory, name))
    out = {}
    for speaker, files in by.items():
        rng.shuffle(files)
        made = []
        for i in range(NOTES_PER_SPEAKER):
            pcm, rate = b"", None
            for f in files[i * DIGITS_PER_NOTE:(i + 1) * DIGITS_PER_NOTE]:
                p, r = read(f)
                rate = r
                pcm += p + b"\x00\x00" * (r // 6)
            made.append((pcm, rate))
        out[speaker] = made
    return out


def to_float(pcm):
    return np.frombuffer(pcm, dtype="<i2").astype(np.float32) / 32768.0


def eer(target, nontarget):
    scores = sorted([(s, 1) for s in target] + [(s, 0) for s in nontarget])
    n_t, n_n = len(target), len(nontarget)
    fr, fa = 0, n_n
    best = 1.0
    for s, is_t in scores:
        if is_t:
            fr += 1
        else:
            fa -= 1
        best = min(best, max(fr / n_t, fa / n_n))
    return best * 100


def main(directory):
    from resemblyzer import VoiceEncoder, preprocess_wav
    enc = VoiceEncoder("cpu", verbose=False)
    rng = random.Random()
    corpus = notes(directory, rng)

    def embed(pcm, rate):
        wav = preprocess_wav(to_float(pcm), source_sr=rate)
        return enc.embed_utterance(wav)

    def masked(pcm, rate, mode):
        return bytes(otrv4_core.voice_mask(pcm, rate, mode)), 16000

    rows = []
    for mode in ("natural", "disguise", "synthetic"):
        clear = {s: [embed(p, r) for p, r in ns] for s, ns in corpus.items()}
        if mode == "natural":
            test = clear
        else:
            test = {s: [embed(*masked(p, r, mode)) for p, r in ns] for s, ns in corpus.items()}

        def trials(enrol_set, test_set):
            t, n = [], []
            for s, es in enrol_set.items():
                model = np.mean(es[:ENROL], axis=0)
                model /= np.linalg.norm(model)
                for s2, ts in test_set.items():
                    for e in ts[ENROL:]:
                        (t if s == s2 else n).append(float(np.dot(model, e)))
            return t, n

        ignorant = eer(*trials(clear, test))
        linking = eer(*trials(test, test))
        rows.append((mode, ignorant, linking))
        print("%-10s ignorant EER %5.1f %%   linking EER %5.1f %%" % (mode, ignorant, linking),
              flush=True)
    return rows




WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]


def intelligibility(directory, n=300):
    """Digit accuracy of an offline recogniser (pocketsphinx, a digits
    grammar) on single spoken digits, before and after the mask. A rough
    proxy for "can the other person still understand it"."""
    import tempfile
    from pocketsphinx import Decoder
    gram = os.path.join(tempfile.mkdtemp(), "digits.gram")
    with open(gram, "w") as f:
        f.write("#JSGF V1.0;\ngrammar d;\npublic <d> = %s;\n" % " | ".join(WORDS))
    dec = Decoder(samprate=16000, jsgf=gram, lm=None)
    files = sorted(f for f in os.listdir(directory) if f.endswith(".wav"))
    random.Random(2).shuffle(files)
    files = files[:n]

    def recognise(pcm):
        dec.start_utt()
        dec.process_raw(pcm, full_utt=True)
        dec.end_utt()
        h = dec.hyp()
        return h.hypstr.strip() if h else ""

    out = {}
    for mode in ("natural", "disguise", "synthetic"):
        right = 0
        for name in files:
            pcm, rate = read(os.path.join(directory, name))
            pad = b"\x00\x00" * (rate // 3)
            got = bytes(otrv4_core.voice_mask(pad + pcm + pad, rate, mode))
            if recognise(got + b"\x00\x00" * 3200) == WORDS[int(name[0])]:
                right += 1
        out[mode] = 100.0 * right / len(files)
        print("%-10s digit accuracy %5.1f %%" % (mode, out[mode]), flush=True)
    return out


def averaged(directory, runs=3):
    """EERs averaged over [runs] runs (every run draws new mask settings)."""
    sums = defaultdict(lambda: [0.0, 0.0])
    for _ in range(runs):
        for mode, ign, link in main(directory):
            sums[mode][0] += ign / runs
            sums[mode][1] += link / runs
    for mode, (ign, link) in sums.items():
        print("MEAN %-10s ignorant EER %5.1f %%   linking EER %5.1f %%" % (mode, ign, link))


if __name__ == "__main__":
    averaged(sys.argv[1])
    intelligibility(sys.argv[1])
