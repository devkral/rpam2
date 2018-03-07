module Rpam2
  VERSION = 3.1
  class << self
    def auth(*args)
      case args.size
        when 3
          self._auth(*args, nil, nil)
        when 5
          self._auth(*args)
        else
          raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 3 or 5)"
      end
    end

    def getenv(*args)
      case args.size
        when 4
          self._getenv(*args, nil, nil, nil)
        when 5
          self._getenv(*args, nil, nil)
        when 7
          self._getenv(*args)
        else
          raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 4, 5 or 7)"
      end
    end

    def listenv(*args)
      case args.size
        when 3
          self._listenv(*args, nil, nil, nil)
        when 4
          self._listenv(*args, nil, nil)
        when 6
          self._listenv(*args)
        else
          raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 3, 4 or 6)"
      end
    end
  end
end

require "rpam2/rpam2"
