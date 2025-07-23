const successResponse = (
    statusCode: number,
    message: string,
    data: Record<string, unknown> | null
) => {
    return {
        success: true,
        status: "success",
        statusCode,
        message,
        data,
    };
};

const errorResponse = (statusCode: number, message: string) => {
    return {
        success: false,
        status: "error",
        statusCode,
        message,
    };
};

export { successResponse, errorResponse };
