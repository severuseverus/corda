package net.corda.nodeapi.internal.serialization

val serializationContextKey = net.corda.core.serialization.SerializeAsTokenContext::class.java

fun net.corda.core.serialization.SerializationContext.withTokenContext(serializationContext: net.corda.core.serialization.SerializeAsTokenContext): net.corda.core.serialization.SerializationContext = this.withProperty(serializationContextKey, serializationContext)

/**
 * A context for mapping SerializationTokens to/from SerializeAsTokens.
 *
 * A context is initialised with an object containing all the instances of [SerializeAsToken] to eagerly register all the tokens.
 * In our case this can be the [ServiceHub].
 *
 * Then it is a case of using the companion object methods on [SerializeAsTokenSerializer] to set and clear context as necessary
 * when serializing to enable/disable tokenization.
 */
class SerializeAsTokenContextImpl(override val serviceHub: net.corda.core.node.ServiceHub, init: net.corda.core.serialization.SerializeAsTokenContext.() -> Unit) : net.corda.core.serialization.SerializeAsTokenContext {
    constructor(toBeTokenized: Any, serializationFactory: net.corda.core.serialization.SerializationFactory, context: net.corda.core.serialization.SerializationContext, serviceHub: net.corda.core.node.ServiceHub) : this(serviceHub, {
        serializationFactory.serialize(toBeTokenized, context.withTokenContext(this))
    })

    private val classNameToSingleton = mutableMapOf<String, net.corda.core.serialization.SerializeAsToken>()
    private var readOnly = false

    init {
        /**
         * Go ahead and eagerly serialize the object to register all of the tokens in the context.
         *
         * This results in the toToken() method getting called for any [SingletonSerializeAsToken] instances which
         * are encountered in the object graph as they are serialized and will therefore register the token to
         * object mapping for those instances.  We then immediately set the readOnly flag to stop further adhoc or
         * accidental registrations from occuring as these could not be deserialized in a deserialization-first
         * scenario if they are not part of this iniital context construction serialization.
         */
        init(this)
        readOnly = true
    }

    override fun putSingleton(toBeTokenized: net.corda.core.serialization.SerializeAsToken) {
        val className = toBeTokenized.javaClass.name
        if (className !in classNameToSingleton) {
            // Only allowable if we are in SerializeAsTokenContext init (readOnly == false)
            if (readOnly) {
                throw UnsupportedOperationException("Attempt to write token for lazy registered ${className}. All tokens should be registered during context construction.")
            }
            classNameToSingleton[className] = toBeTokenized
        }
    }

    override fun getSingleton(className: String) = classNameToSingleton[className] ?: throw IllegalStateException("Unable to find tokenized instance of $className in context $this")
}