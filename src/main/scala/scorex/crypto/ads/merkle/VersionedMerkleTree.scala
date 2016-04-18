package scorex.crypto.ads.merkle

import scorex.crypto.ads._
import scorex.crypto.hash.CryptographicHash

import scala.annotation.tailrec
import scala.collection.mutable
import scala.util.{Failure, Success, Try}


trait VersionedMerkleTree[HashFn <: CryptographicHash, ST <: StorageType]
  extends MerkleTree[HashFn, ST] with VersionedStorage[ST] {

  override protected type Level = VersionedLazyIndexedBlobStorage[ST]

  private def even(l: Long) = (l % 2) == 0

  @tailrec
  final def batchUpdate(changes: Seq[(Position, Option[Digest])],
                        level: Int = 0): VersionedMerkleTree[HashFn, ST] = {
    val levelMap = getLevel(level).get

    val pairs = mutable.Map[Position, Option[(Digest, Digest)]]()

    changes.foreach { case (pos, newDigestOpt) =>
      newDigestOpt match {
        case Some(nd) =>
          levelMap.set(pos, nd)
        case None =>
          levelMap.unset(pos)
      }

      even(pos) match {
        //left
        case true =>
          pairs.put(pos, newDigestOpt.map(newDigest => (newDigest, levelMap.get(pos + 1).getOrElse(emptyHash))))

        //right
        case false =>
          val leftPos = pos - 1

          pairs.get(leftPos) match {
            case Some(pairOpt) =>
              (pairOpt, newDigestOpt) match {
                case (Some(pair), _) =>
                  pairs.put(leftPos, Some(pair._1, newDigestOpt.getOrElse(emptyHash)))
                case (None, Some(newDigest)) =>
                  throw new IllegalStateException("This branch must not be reached")
                case (None, None) => //leave None
              }

            case None =>
              //todo: get?
              pairs.put(leftPos, Some(levelMap.get(leftPos).getOrElse(emptyHash), newDigestOpt.getOrElse(emptyHash)))
          }
      }
    }

    val nextLevelChanges = pairs.map { case (pos, dsOpt) =>
      pos / 2 -> dsOpt.map(ds => hashFunction(ds._1 ++ ds._2))
    }.toSeq

    if (level == height) {
      commit()
      this
    } else {
      batchUpdate(nextLevelChanges, level + 1)
    }
  }

  def close(): Unit

  def commit(): Unit

  protected def mapLevels[T](mapFn: Level => T): Try[Seq[T]] =
    (0 to height).foldLeft(Success(Seq()): Try[Seq[T]]) { case (partialResult, i) =>
      partialResult match {
        case Failure(e) =>
          Failure(new Exception(s"Has a problem why reverting a level $i", e))
        case Success(seq) =>
          Try(getLevel(i).get).map(mapFn).map(e => seq :+ e)
      }
    }

  override def putVersionTag(versionTag: VersionTag): Unit =
    mapLevels(_.putVersionTag(versionTag)) //todo: Try[Unit] ?

  override def rollbackTo(versionTag: VersionTag): Try[VersionedMerkleTree[HashFn, ST]] =
    mapLevels(_.rollbackTo(versionTag)).flatMap(_.find(_.isFailure) match {
      case Some(Failure(thr)) => Failure(thr)
      case Some(_) => Failure(new Exception("Some(_)"))
      case None => Success(this)
    })

  override def allVersions(): Seq[VersionTag] = getLevel(0).map(_.allVersions()).getOrElse(Seq())

  def consistent: Boolean = mapLevels(_.lastVersion).map(_.toSet.size == 1).getOrElse(false)

  def repair() = ??? //todo: implement
}


abstract class MvStoreVersionedMerkleTree[HashFn <: CryptographicHash](val fileNameOpt: Option[String],
                                                                       override val hashFunction: HashFn)
  extends VersionedMerkleTree[HashFn, MvStoreStorageType] {

  protected lazy val levels = mutable.Map[Int, VersionedLazyIndexedBlobStorage[MvStoreStorageType]]()

  protected def createLevel(level: LevelId): Try[Level] = Try {
    val res = new MvStoreVersionedLazyIndexedBlobStorage(fileNameOpt.map(_ + "-" +level + ".mapDB"))
    levels += level -> res
    res
  }.recoverWith{case e:Throwable =>
      e.printStackTrace()
      Failure(e)
  }

  protected def getLevel(level: LevelId): Option[Level] =
    levels.get(level).orElse(createLevel(level).toOption)

  override def close(): Unit = {
    commit()
    levels.foreach(_._2.close())
  }

  override def commit(): Unit = levels.foreach(_._2.commitAndMark())
}

object MvStoreVersionedMerkleTree {
  def apply[HashFn <: CryptographicHash](seq: VersionedLazyIndexedBlobStorage[_],
                                         fileNameOpt: Option[String],
                                         hashFunction: HashFn): MvStoreVersionedMerkleTree[HashFn] = {
    val tree = new MvStoreVersionedMerkleTree(fileNameOpt, hashFunction) {
      override def size = seq.size
    }.ensuring(_.levels(0).size == 0)
    val leafsMap = tree.levels(0)
    (0L to seq.size - 1).foreach(i => leafsMap.set(i, hashFunction(seq.get(i).get)))
    tree.commit() //todo: initial version
    tree
  }
}