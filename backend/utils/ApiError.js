class ApiError extends Error {
    constructor(statusCode, message = "Something Went Wrong", errors = [], stack = "") {
        super(message)
        this.statusCode = statusCode
        this.message = message
        this.success = false
        this.errors = errors
        if (stack) {
            this.stack = stack;
        } else {
            stack = Error.captureStackTrace(this, this.constructor)
        }
    }
}

export default ApiError