# frozen_string_literal: true

# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

class ProjectsController < InheritedResources::Base
  private

  def project_params
    params.require(:project).permit(:title, :short_description, :full_description, :website_url, :github_url,
                                    :discord_url, :twitter_url, :telegram_url, :linkedin_url, :thumbnail_url,
                                    :youtube_url, :forum_url, :public)
  end
end
