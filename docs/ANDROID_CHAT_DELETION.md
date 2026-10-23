<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Deleting a chat (Android)

What "Delete chat" does, what it does not do, and what the app will and will
not claim about the server. The policy and the user-facing text are in
`chat/ChatDeletion.kt`. The mechanism is `ChatState.deleteConversation`,
`MessageStore.delete` and `DeletedConversations`. `ChatDeletionTest` and
`tests/test_android_chat_deletion.py` cover them.

**Handset status: not yet run on a device.** See §12 of
[ANDROID_CALL_AND_FILE_DEVICE_TEST.md](ANDROID_CALL_AND_FILE_DEVICE_TEST.md).

## How to use it

Long-press a row in the conversation list, then confirm. Nothing is deleted
without the confirmation.

## One-to-one conversations

| | Effect |
|---|---|
| Messages on this device | **Deleted.** The conversation's vault record is removed, and the index is rewritten without it. |
| Draft, unread count | Deleted |
| The row | Stays gone across restarts and roster polls. `DeletedConversations` keeps the address, sealed in the vault. A new message, a send, or opening the conversation brings the row back. |
| Server roster (the contact) | **Kept.** Removing a contact is "Remove contact", which is a separate action. |
| OTR session, fingerprint trust, SMP verification | Kept. They describe the peer, not what was said. |
| Server-side copies | **Not deleted.** See below. |

## Rooms

Rooms are XEP-0045 multi-user chat (`slixmpp` `xep_0045`), not MUC Light. The
app keeps no bookmarks.

| Action | Where | What it does |
|---|---|---|
| Delete chat | conversation list | Deletes the room's messages on this device and hides the row. Staying in the room means new messages bring it back. |
| Delete and leave room | same dialog, only when this session is in the room | The above, plus leaving. The room still exists for everyone else. |
| Leave | Rooms screen | Leaves the room. Nothing is deleted. |
| Destroy | Rooms screen only; owners only; separate confirmation | Deletes the room for everyone. |

**Deleting a chat never destroys a room.** The deletion path does not reach
`destroy_room`, and a test asserts it.

A room's stored history now stays a room after a restart. Stored lines carry
the sender's nickname, and `ChatState.isRoom` reads it. Before this change,
membership was forgotten when the stream dropped, and a room's history came
back looking like a one-to-one chat with the room's address.

## Server-side deletion

**Not supported, and never claimed.** No XEP lets a client delete a server's
message archive:

- XEP-0313 (MAM) defines queries only.
- XEP-0424 (retraction) asks the other side's clients to hide one message,
  identified by an archive id. This app does not record those ids.
- XEP-0425 (moderation) is per message, and only for room moderators.

After a local delete, the app asks the server with one disco#info query
(`archive_support`: our own account for a one-to-one chat, the room for a
room). It then tells the user what the server said:

- *"the server keeps a message archive and its copy was not deleted"*. For
  encrypted one-to-one messages, that copy is OTR ciphertext.
- *"the server advertises no message archive"*.
- *"whether the server keeps a copy could not be checked"*, when offline or
  with no answer. Unknown is never reported as "no archive".

Every message begins its server clause with "Server-side deletion is not
supported". A test checks that no outcome ever says the server deleted
anything.

## What deletion means on the disk

The vault record is removed. The record was AES-256-GCM under the
AndroidKeyStore key, so what remains on flash is ciphertext under a key that
still exists until Wipe & Exit. Deleting one chat is therefore **deletion,
not cryptographic erasure**. Only Wipe & Exit, which deletes the key, is
erasure. Physical flash erasure is claimed for neither.

## Sign out

Sign out now also forgets the deleted-conversation list and the saved-contact
list. Before this change it left the saved-contact list behind, although the
documentation said the list went with the account.
