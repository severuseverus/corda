package net.corda.node.utilities

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import net.corda.core.schemas.MappedSchema
import net.corda.core.serialization.*
import net.corda.node.services.database.HibernateConfiguration
import net.corda.node.services.schema.NodeSchemaService
import org.hibernate.SessionFactory
import org.jetbrains.exposed.sql.Database

import rx.Observable
import rx.Subscriber
import rx.subjects.UnicastSubject
import java.io.Closeable
import java.sql.Connection
import java.sql.SQLException
import java.util.*
import java.util.concurrent.CopyOnWriteArrayList


//HikariDataSource implements Closeable which allows CordaPersistence to be Closeable
class CordaPersistence(var dataSource: HikariDataSource, var nodeSchemaService: NodeSchemaService, databaseProperties: Properties): Closeable {

    /** Holds Exposed database, the field will be removed once Exposed library is removed */
    lateinit var database: Database
    var transactionIsolationLevel = parserTransactionIsolationLevel(databaseProperties.getProperty("transactionIsolationLevel"))

    val entityManagerFactory: SessionFactory by lazy(LazyThreadSafetyMode.NONE) {
        transaction {
            HibernateConfiguration(nodeSchemaService, databaseProperties = databaseProperties).sessionFactoryForRegisteredSchemas()
        }
    }

    companion object {
        fun connect(dataSource: HikariDataSource, nodeSchemaService: NodeSchemaService, databaseProperties: Properties): CordaPersistence {
            return CordaPersistence(dataSource, nodeSchemaService, databaseProperties).apply {
                DatabaseTransactionManager(this)
            }
        }
    }

    fun createTransaction(): DatabaseTransaction {
        // We need to set the database for the current [Thread] or [Fiber] here as some tests share threads across databases.
        DatabaseTransactionManager.dataSource = this
        return DatabaseTransactionManager.currentOrNew(transactionIsolationLevel)
    }

    fun <T> transaction(statement: DatabaseTransaction.() -> T): T {
        DatabaseTransactionManager.dataSource = this
        return transaction(transactionIsolationLevel, 3, statement)
    }

    private fun <T> transaction(transactionIsolation: Int, repetitionAttempts: Int, statement: DatabaseTransaction.() -> T): T {
        val outer = DatabaseTransactionManager.currentOrNull()

        return if (outer != null) {
            outer.statement()
        }
        else {
            inTopLevelTransaction(transactionIsolation, repetitionAttempts, statement)
        }
    }

    private fun <T> inTopLevelTransaction(transactionIsolation: Int, repetitionAttempts: Int, statement: DatabaseTransaction.() -> T): T {
        var repetitions = 0
        while (true) {
            val transaction = DatabaseTransactionManager.currentOrNew(transactionIsolation)
            try {
                val answer = transaction.statement()
                transaction.commit()
                return answer
            }
            catch (e: SQLException) {
                transaction.rollback()
                repetitions++
                if (repetitions >= repetitionAttempts) {
                    throw e
                }
            }
            catch (e: Throwable) {
                transaction.rollback()
                throw e
            }
            finally {
                transaction.close()
            }
        }
    }

    override fun close() {
        dataSource.close()
    }
}

fun configureDatabase(dataSourceProperties: Properties, databaseProperties: Properties?, entitySchemas : Set<MappedSchema> = emptySet<MappedSchema>()): CordaPersistence {
    val config = HikariConfig(dataSourceProperties)
    val dataSource = HikariDataSource(config)
    val persistence = CordaPersistence.connect(dataSource, NodeSchemaService(entitySchemas), databaseProperties ?: Properties())

    //org.jetbrains.exposed.sql.Database will be removed once Exposed library is removed
    val database = Database.connect(dataSource) { _ -> ExposedTransactionManager() }
    persistence.database = database

    // Check not in read-only mode.
    persistence.transaction {
        persistence.dataSource.connection.use {
            check(!it.metaData.isReadOnly) { "Database should not be readonly." }
        }
    }
    return persistence
}

/**
 * Buffer observations until after the current database transaction has been closed.  Observations are never
 * dropped, simply delayed.
 *
 * Primarily for use by component authors to publish observations during database transactions without racing against
 * closing the database transaction.
 *
 * For examples, see the call hierarchy of this function.
 */
fun <T : Any> rx.Observer<T>.bufferUntilDatabaseCommit(): rx.Observer<T> {
    val currentTxId = DatabaseTransactionManager.transactionId
    val databaseTxBoundary: Observable<DatabaseTransactionManager.Boundary> = DatabaseTransactionManager.transactionBoundaries.filter { it.txId == currentTxId }.first()
    val subject = UnicastSubject.create<T>()
    subject.delaySubscription(databaseTxBoundary).subscribe(this)
    databaseTxBoundary.doOnCompleted { subject.onCompleted() }
    return subject
}

// A subscriber that delegates to multiple others, wrapping a database transaction around the combination.
private class DatabaseTransactionWrappingSubscriber<U>(val db: CordaPersistence?) : Subscriber<U>() {
    // Some unsubscribes happen inside onNext() so need something that supports concurrent modification.
    val delegates = CopyOnWriteArrayList<Subscriber<in U>>()

    fun forEachSubscriberWithDbTx(block: Subscriber<in U>.() -> Unit) {
        (db ?: DatabaseTransactionManager.dataSource).transaction {
            delegates.filter { !it.isUnsubscribed }.forEach {
                it.block()
            }
        }
    }

    override fun onCompleted() = forEachSubscriberWithDbTx { onCompleted() }

    override fun onError(e: Throwable?) = forEachSubscriberWithDbTx { onError(e) }

    override fun onNext(s: U) = forEachSubscriberWithDbTx { onNext(s) }

    override fun onStart() = forEachSubscriberWithDbTx { onStart() }

    fun cleanUp() {
        if (delegates.removeIf { it.isUnsubscribed }) {
            if (delegates.isEmpty()) {
                unsubscribe()
            }
        }
    }
}

// A subscriber that wraps another but does not pass on observations to it.
private class NoOpSubscriber<U>(t: Subscriber<in U>) : Subscriber<U>(t) {
    override fun onCompleted() {
    }

    override fun onError(e: Throwable?) {
    }

    override fun onNext(s: U) {
    }
}

/**
 * Wrap delivery of observations in a database transaction.  Multiple subscribers will receive the observations inside
 * the same database transaction.  This also lazily subscribes to the source [rx.Observable] to preserve any buffering
 * that might be in place.
 */
fun <T : Any> rx.Observable<T>.wrapWithDatabaseTransaction(db: CordaPersistence? = null): rx.Observable<T> {
    var wrappingSubscriber = DatabaseTransactionWrappingSubscriber<T>(db)
    // Use lift to add subscribers to a special subscriber that wraps a database transaction around observations.
    // Each subscriber will be passed to this lambda when they subscribe, at which point we add them to wrapping subscriber.
    return this.lift { toBeWrappedInDbTx: Subscriber<in T> ->
        // Add the subscriber to the wrapping subscriber, which will invoke the original subscribers together inside a database transaction.
        wrappingSubscriber.delegates.add(toBeWrappedInDbTx)
        // If we are the first subscriber, return the shared subscriber, otherwise return a subscriber that does nothing.
        if (wrappingSubscriber.delegates.size == 1) wrappingSubscriber else NoOpSubscriber(toBeWrappedInDbTx)
        // Clean up the shared list of subscribers when they unsubscribe.
    }.doOnUnsubscribe {
        wrappingSubscriber.cleanUp()
        // If cleanup removed the last subscriber reset the system, as future subscribers might need the stream again
        if (wrappingSubscriber.delegates.isEmpty()) {
            wrappingSubscriber = DatabaseTransactionWrappingSubscriber<T>(db)
        }
    }
}

fun parserTransactionIsolationLevel(property: String?) : Int =
        when (property) {
            "none" -> Connection.TRANSACTION_NONE
            "readUncommitted" -> Connection.TRANSACTION_READ_UNCOMMITTED
            "readCommitted" -> Connection.TRANSACTION_READ_COMMITTED
            "repeatableRead" -> Connection.TRANSACTION_REPEATABLE_READ
            "serializable" -> Connection.TRANSACTION_SERIALIZABLE
            else -> {
                Connection.TRANSACTION_REPEATABLE_READ
            }
        }

fun <T: Any> deserializeFromByteArray(blob: ByteArray, context: SerializationContext): T = SerializedBytes<Any>(blob).deserialize(context = context) as T
fun <T: Any> serializeToByteArray(value: T, context: SerializationContext): ByteArray = value.serialize(context = context).bytes