import JWT from 'jsonwebtoken'

/**
 * Function tạo mới token cần 3 tham số đầu vào
 * userInfo: Những thông tin muốn đính kèm vào token
 * secretSignature: Chữ ký bí mật (1 chuỗi string ngẫu nhiên)
 * tokenLife
 */
const generateToken = async (userInfo, secretSignature, tokenLife) => {
  try {
    return JWT.sign(userInfo, secretSignature, { algorithm: 'HS256', expiresIn: tokenLife })
  } catch (error) {
    throw new Error(error)
  }
}

/**
 * Function kiểm tra tính hợp lệ của token
 * Hiểu đơn giản là kiểm tra xem token được tạo ra có đúng với secretSignature trong dự án hay không
 */
const verifyToken = async (token, secretSignature) => {
  try {
    return JWT.verify(token, secretSignature)
  } catch (error) {
    throw new Error(error)
  }
}

export const JwtProvider = {
  generateToken,
  verifyToken
}