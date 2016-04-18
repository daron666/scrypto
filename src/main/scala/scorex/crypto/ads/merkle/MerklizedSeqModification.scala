package scorex.crypto.ads.merkle

sealed trait MerklizedSeqModification

final case class MerklizedSeqAppend(element: Array[Byte]) extends MerklizedSeqModification

final case class MerklizedSeqRemoval(position: Position) extends MerklizedSeqModification
