import React, { createContext, useContext, useEffect, useState } from 'react'
import { useHistory } from 'react-router-dom'
import { generateEG } from '../../../lib'

const ChatContext = createContext(null)

const ChatProvider = ({ children }) => {
  const [selectedChat, setSelectedChat] = useState()
  const [user, setUser] = useState()
  const [notification, setNotification] = useState([])
  const [chats, setChats] = useState()
  const [govKeyPair, setGovKeyPair] = useState({})

  const history = useHistory()

  useEffect(() => {
    generateEG().then(data => setGovKeyPair(data))
  }, [])

  useEffect(() => {
    const userInfo = JSON.parse(localStorage.getItem('userInfo'))
    setUser(userInfo)

    if (!userInfo) history.push('/')
  }, [history])

  return (
    <ChatContext.Provider
      value={{
        selectedChat,
        setSelectedChat,
        user,
        setUser,
        notification,
        setNotification,
        chats,
        setChats,
        govKeyPair
      }}
    >
      {children}
    </ChatContext.Provider>
  )
}

export const ChatState = () => {
  return useContext(ChatContext)
}

export default ChatProvider
