module ::MItamae
  module Plugin
    module Resource
      class GpgKeyring < ::MItamae::Resource::File
        define_attribute :fingerprint, type: String, required: true
        define_attribute :user_id, type: String
        define_attribute :url, type: String
        define_attribute :keyserver, type: String

        self.available_actions = [:create, :delete]
      end
    end
  end
end
