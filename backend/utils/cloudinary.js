import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_CLOUD_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) {
            console.error("No file path provided");
            return null;
        }

        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto",
        });

        console.log("File uploaded successfully:", response.url);

        // Attempt to delete the local file
        if (fs.existsSync(localFilePath)) {
            fs.unlinkSync(localFilePath);
            console.log("Temporary file deleted successfully");
        } else {
            console.warn("Temporary file not found for deletion");
        }

        return response;
    } catch (error) {
        console.error("Error uploading file to Cloudinary:", error.message);

        // Safely attempt to delete the local file
        try {
            if (fs.existsSync(localFilePath)) {
                fs.unlinkSync(localFilePath);
                console.log("Temporary file deleted after error");
            }
        } catch (unlinkError) {
            console.error("Error deleting temporary file:", unlinkError.message);
        }

        return null;
    }
};

export { uploadOnCloudinary };