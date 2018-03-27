
require 'set'

require 'rpam2/rpam2'

module Rpam2
  VERSION = 4.0
  class << self
    attr_accessor :fake_data
    @@fake_data = nil

    def auth(*args)
      case args.size
        when 3
          _auth(*args, nil, nil)
        when 5
          _auth(*args)
        else
          raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 3 or 5)"
      end
    end

    def account(servicename, username)
      _account(servicename, username)
    end

    def getenv(*args)
      case args.size
        when 4
          _getenv(*args, nil, nil, nil)
        when 5
          _getenv(*args, nil, nil)
        when 7
          _getenv(*args)
        else
          raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 4, 5 or 7)"
      end
    end

    def listenv(*args)
      case args.size
        when 3
          _listenv(*args, nil, nil, nil)
        when 4
          _listenv(*args, nil, nil)
        when 6
          _listenv(*args)
        else
          raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 3, 4 or 6)"
      end
    end

    private

    def use_fake?(servicename)
      return false unless self.fake_data
      self.fake_data.fetch(:servicenames, Set.new).include?(servicename)
    end

    def _auth(servicename, username, password, ruser, rhost)
      raise TypeError unless username.is_a? String
      raise TypeError unless password.is_a? String
      return _authc(servicename, username, password, ruser, rhost) unless use_fake?(servicename)
      self.fake_data[:password] == password && self.fake_data.fetch(:usernames, Set.new).include?(username)
    end

    def _account(servicename, username)
      raise TypeError unless username.is_a? String
      return _accountc(servicename, username) unless use_fake?(servicename)
      self.fake_data.fetch(:usernames, Set.new).include?(username)
    end

    def _getenv(servicename, username, password, varname, opensession, ruser, rhost)
      raise TypeError unless username.is_a? String
      raise TypeError unless password.is_a? String
      raise TypeError unless varname.is_a? String
      return _getenvc(servicename, username, password, varname, opensession, ruser, rhost) unless use_fake?(servicename)
      return nil unless self.fake_data.fetch(:usernames, Set.new).include?(username)
      return nil unless self.fake_data[:env] && self.fake_data[:password] == password
      self.fake_data[:env].fetch(varname, nil)
    end

    def _listenv(servicename, username, password, opensession, ruser, rhost)
      raise TypeError unless username.is_a? String
      raise TypeError unless password.is_a? String
      return _listenvc(servicename, username, password, opensession, ruser, rhost) unless use_fake?(servicename)
      return nil unless self.fake_data[:password] == password && self.fake_data.fetch(:usernames, Set.new).include?(username)
      self.fake_data.fetch(:env, {})
    end
  end
  private_class_method :_authc, :_accountc, :_getenvc, :_listenvc
end
