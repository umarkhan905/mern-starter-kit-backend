import mjml2html from "mjml";
import fs from "fs";
import path from "path";

export const parseMJML = (fileName: string) => {
    const __dirname = import.meta.dirname;
    const filePath = path.join(__dirname, `../emails/${fileName}.mjml`);
    const mjml = fs.readFileSync(filePath, "utf-8");
    return mjml2html(mjml).html;
};
