import { StatusCodes } from 'http-status-codes'
import { JwtProvider, ACCESS_TOKEN_SECRET_SIGNATURE } from '~/providers/JwtProvider'

// Middleware nhận và xác thực xem accessToken có hợp lệ hay không. Chỉ sử dụng 1 trong 2 cách lấy token là cookies và headers
const isAuthorized = async (req, res, next) => {
  // Cách 1: Lấy accessToken thông qua request cookies phía client - withCredentials
  const accessTokenFromCookie = req.cookies?.accessToken

  if (!accessTokenFromCookie) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized! (Token not found!)' })
    return
  }

  // Cách 2: Lấy accessToken thông qua headers Authorization, khi client đính kèm token lưu trong localstorage
  const accessTokenFromHeader = req.headers?.authorization

  if (!accessTokenFromHeader) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized! (Token not found!)' })
    return
  }

  try {
    // Bước 1: Giải mã token xem có hợp lệ hay không
    const accessTokenDecoded = await JwtProvider.verifyToken(
      // accessTokenFromCookie,
      accessTokenFromHeader.substring('Bearer '.length),
      ACCESS_TOKEN_SECRET_SIGNATURE
    )

    // Bước 2: Nếu token hợp lệ, thì lưu thông tin giải mã được (payload) vào req.jwtDecoded, để sử dụng cho các tầng phía sau xử lý
    req.jwtDecoded = accessTokenDecoded

    // Bước 3: Cho phép request đi tiếp
    next()
  } catch (error) {
    // Nếu accessToken hết hạn thì trả về mã lỗi 410 để phía FE biết gọi api refreshToken
    if (error.message?.includes('jwt expired')) {
      res.status(StatusCodes.GONE).json({ message: 'Need to refresh token!' })
      return
    }

    // Nếu accessToken không hợp lệ thì trả về mã lỗi 401 để phía FE logout
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized! Please login!' })
  }
}

export const authMiddleware = {
  isAuthorized
}